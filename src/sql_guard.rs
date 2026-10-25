//! Lexical guard against statements that leave session state on a shared server connection.
//!
//! Defence in depth: the read path never issues these, and a changed server-reported parameter
//! is caught separately when the connection returns to its pool. The lexer follows PostgreSQL's
//! rules for comments, quoted identifiers and string literals so keywords inside them are
//! ignored. It assumes the server parameters in [`ASSUMED_PARAMETERS`].

/// Server parameters the lexer assumes. Under other values the server splits a query string
/// differently, so a statement the guard read as a literal may run.
pub const ASSUMED_PARAMETERS: [(&str, &str); 2] = [
    ("standard_conforming_strings", "on"),
    ("client_encoding", "UTF8"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    pub statement: &'static str,
}

/// Rejects `SET` (except `SET LOCAL` and `SET TRANSACTION`), `RESET`, `DISCARD`, `PREPARE`,
/// `LISTEN` and `DECLARE … WITH HOLD` anywhere in a possibly multi-statement query string.
pub fn check(sql: &str) -> Result<(), Rejected> {
    let mut lexer = Lexer {
        src: sql.as_bytes(),
        pos: 0,
    };
    let mut statement = Statement::default();
    loop {
        match lexer.next_token() {
            Token::Word(word) => statement.push(word),
            // Only words matter; anything else just separates them.
            Token::Other => statement.push(b""),
            Token::Semicolon => {
                statement.check()?;
                statement = Statement::default();
            }
            Token::End => return statement.check(),
        }
    }
}

fn is(word: &[u8], keyword: &str) -> bool {
    word.eq_ignore_ascii_case(keyword.as_bytes())
}

/// What the guard needs from one statement, in constant space however long it is.
#[derive(Default)]
struct Statement<'a> {
    first: Option<&'a [u8]>,
    second: Option<&'a [u8]>,
    previous: &'a [u8],
    /// `DECLARE` reached its `FOR`, after which `WITH HOLD` is part of the query.
    declare_done: bool,
    with_hold: bool,
}

impl<'a> Statement<'a> {
    fn push(&mut self, token: &'a [u8]) {
        let Some(first) = self.first else {
            self.first = Some(token);
            return;
        };
        if self.second.is_none() {
            self.second = Some(token);
        }
        // DECLARE name [BINARY] [ASENSITIVE | INSENSITIVE] [[NO] SCROLL] CURSOR [{WITH | WITHOUT} HOLD] FOR query
        if is(first, "declare") && !self.declare_done {
            if is(token, "for") {
                self.declare_done = true;
            } else if is(self.previous, "with") && is(token, "hold") {
                self.with_hold = true;
            }
        }
        self.previous = token;
    }

    fn check(&self) -> Result<(), Rejected> {
        let Some(first) = self.first else {
            return Ok(());
        };
        let second = self.second.unwrap_or_default();
        let reject = |statement| Err(Rejected { statement });
        if is(first, "set") {
            if is(second, "local") || is(second, "transaction") {
                return Ok(());
            }
            return reject("SET");
        }
        for (keyword, statement) in [
            ("reset", "RESET"),
            ("discard", "DISCARD"),
            ("prepare", "PREPARE"),
            ("listen", "LISTEN"),
        ] {
            if is(first, keyword) {
                return reject(statement);
            }
        }
        if self.with_hold {
            return reject("DECLARE ... WITH HOLD");
        }
        Ok(())
    }
}

enum Token<'a> {
    Word(&'a [u8]),
    Semicolon,
    Other,
    End,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_' || b >= 0x80
}

fn is_ident_cont(b: u8) -> bool {
    is_ident_start(b) || b.is_ascii_digit() || b == b'$'
}

impl<'a> Lexer<'a> {
    fn peek(&self, offset: usize) -> Option<u8> {
        self.src.get(self.pos + offset).copied()
    }

    fn next_token(&mut self) -> Token<'a> {
        loop {
            let Some(b) = self.peek(0) else {
                return Token::End;
            };
            match b {
                // PostgreSQL's whitespace also includes vertical tab, which Rust's does not.
                b if b.is_ascii_whitespace() || b == 0x0b => self.pos += 1,
                b'-' if self.peek(1) == Some(b'-') => {
                    while let Some(b) = self.peek(0) {
                        self.pos += 1;
                        if b == b'\n' || b == b'\r' {
                            break;
                        }
                    }
                }
                b'/' if self.peek(1) == Some(b'*') => self.skip_block_comment(),
                b';' => {
                    self.pos += 1;
                    return Token::Semicolon;
                }
                b'\'' => {
                    self.skip_quoted(b'\'', false);
                    return Token::Other;
                }
                b'"' => {
                    self.skip_quoted(b'"', false);
                    return Token::Other;
                }
                b'$' => {
                    self.skip_dollar();
                    return Token::Other;
                }
                b if is_ident_start(b) => return self.word(),
                _ => {
                    self.pos += 1;
                    return Token::Other;
                }
            }
        }
    }

    fn word(&mut self) -> Token<'a> {
        let start = self.pos;
        // E'...' allows backslash escapes; U&'...', B'...', X'...' and N'...' do not.
        if matches!(self.peek(0), Some(b'e' | b'E')) && self.peek(1) == Some(b'\'') {
            self.pos += 1;
            self.skip_quoted(b'\'', true);
            return Token::Other;
        }
        if matches!(self.peek(0), Some(b'u' | b'U'))
            && self.peek(1) == Some(b'&')
            && matches!(self.peek(2), Some(b'\'' | b'"'))
        {
            let quote = self.src[self.pos + 2];
            self.pos += 2;
            self.skip_quoted(quote, false);
            return Token::Other;
        }
        while self.peek(0).is_some_and(is_ident_cont) {
            self.pos += 1;
        }
        Token::Word(&self.src[start..self.pos])
    }

    /// Skips a quoted literal or identifier starting at the opening quote. A doubled quote is an
    /// escaped quote; with `backslash_escapes`, so is `\'`. An unterminated one runs to the end.
    fn skip_quoted(&mut self, quote: u8, backslash_escapes: bool) {
        self.pos += 1;
        while let Some(b) = self.peek(0) {
            self.pos += 1;
            if backslash_escapes && b == b'\\' {
                self.pos = (self.pos + 1).min(self.src.len());
            } else if b == quote {
                if self.peek(0) == Some(quote) {
                    self.pos += 1;
                } else if quote == b'\''
                    && let Some(next) = self.string_continuation()
                {
                    // The continuation keeps the escape rules of the literal it extends.
                    self.pos = next;
                } else {
                    return;
                }
            }
        }
    }

    /// The position after the opening quote of a continuation segment (`'a'` newline `'b'`), as
    /// in PostgreSQL's `quotecontinue`: whitespace or `--` comments that include a newline.
    fn string_continuation(&self) -> Option<usize> {
        let is_horiz_space = |b: u8| matches!(b, b' ' | b'\t' | 0x0c | 0x0b);
        let is_newline = |b: u8| matches!(b, b'\n' | b'\r');
        let skip_comment = |mut pos: usize| {
            while self.src.get(pos).is_some_and(|&b| !is_newline(b)) {
                pos += 1;
            }
            pos
        };
        let starts_comment = |pos: usize| self.src.get(pos..pos + 2) == Some(b"--");
        let mut pos = self.pos;
        loop {
            match self.src.get(pos) {
                Some(&b) if is_horiz_space(b) => pos += 1,
                Some(b'-') if starts_comment(pos) => pos = skip_comment(pos),
                _ => break,
            }
        }
        if !self.src.get(pos).is_some_and(|&b| is_newline(b)) {
            return None;
        }
        pos += 1;
        loop {
            match self.src.get(pos) {
                Some(&b) if is_horiz_space(b) || is_newline(b) => pos += 1,
                Some(b'-') if starts_comment(pos) => {
                    pos = skip_comment(pos);
                    if !self.src.get(pos).is_some_and(|&b| is_newline(b)) {
                        return None;
                    }
                    pos += 1;
                }
                _ => break,
            }
        }
        (self.src.get(pos) == Some(&b'\'')).then_some(pos + 1)
    }

    fn skip_block_comment(&mut self) {
        // Block comments nest in PostgreSQL.
        let mut depth = 0usize;
        while let Some(b) = self.peek(0) {
            if b == b'/' && self.peek(1) == Some(b'*') {
                depth += 1;
                self.pos += 2;
            } else if b == b'*' && self.peek(1) == Some(b'/') {
                depth -= 1;
                self.pos += 2;
                if depth == 0 {
                    return;
                }
            } else {
                self.pos += 1;
            }
        }
    }

    /// Skips `$n` parameters, `$tag$ … $tag$` dollar-quoted strings and a lone `$`.
    fn skip_dollar(&mut self) {
        let start = self.pos;
        self.pos += 1;
        if self.peek(0).is_some_and(|b| b.is_ascii_digit()) {
            while self.peek(0).is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
            return;
        }
        if self.peek(0).is_some_and(is_ident_start) {
            while self
                .peek(0)
                .is_some_and(|b| is_ident_start(b) || b.is_ascii_digit())
            {
                self.pos += 1;
            }
        }
        if self.peek(0) != Some(b'$') {
            // A lone `$` (or `$ident` without a closing `$`) is not a delimiter.
            self.pos = start + 1;
            return;
        }
        self.pos += 1;
        let delimiter = &self.src[start..self.pos];
        let body = &self.src[self.pos..];
        match body.windows(delimiter.len()).position(|w| w == delimiter) {
            Some(end) => self.pos += end + delimiter.len(),
            None => self.pos = self.src.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(sql: &str) -> Option<&'static str> {
        check(sql).err().map(|r| r.statement)
    }

    #[test]
    fn allows_read_path_statements() {
        for sql in [
            "select 1",
            "BEGIN ISOLATION LEVEL REPEATABLE READ",
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY",
            "set local search_path = foo",
            "SAVEPOINT a; RELEASE SAVEPOINT a; ROLLBACK TO SAVEPOINT a",
            "with x as (select 1) select * from x",
            "DECLARE c CURSOR FOR SELECT 1",
            "DECLARE c CURSOR WITHOUT HOLD FOR SELECT 'with hold'",
            "",
            ";;",
        ] {
            assert_eq!(rejected(sql), None, "{sql}");
        }
    }

    #[test]
    fn rejects_session_state() {
        for (sql, statement) in [
            ("SET search_path = x", "SET"),
            ("set session timezone = 'UTC'", "SET"),
            (
                "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY",
                "SET",
            ),
            ("SET SESSION AUTHORIZATION x", "SET"),
            ("SET ROLE x", "SET"),
            ("reset all", "RESET"),
            ("DISCARD ALL", "DISCARD"),
            ("prepare p as select 1", "PREPARE"),
            ("LISTEN x", "LISTEN"),
            (
                "declare c binary cursor with hold for select 1",
                "DECLARE ... WITH HOLD",
            ),
            ("select 1; set x = 1", "SET"),
            (
                "select 1;\n  -- comment\n  /* nested /* comment */ */ Set x = 1",
                "SET",
            ),
            ("select $$;$$; set x = 1", "SET"),
            ("\x0bPREPARE p AS select 1", "PREPARE"),
            ("select 1;\x0bset work_mem = '1GB'", "SET"),
            (
                "\x0bDECLARE c CURSOR WITH HOLD FOR select 1",
                "DECLARE ... WITH HOLD",
            ),
            // A continuation segment keeps the backslash escapes of the E'' it extends.
            ("select E''\n'\\''; SET search_path = evil; --'", "SET"),
            (
                "select E'' -- c\n\t-- d\r\n'\\''; PREPARE p AS select 1; --'",
                "PREPARE",
            ),
        ] {
            assert_eq!(rejected(sql), Some(statement), "{sql}");
        }
    }

    #[test]
    fn ignores_keywords_inside_literals_and_comments() {
        for sql in [
            "select 'a; set x = 1'",
            "select E'it\\'s; set x = 1'",
            "select 'it''s; set x = 1'",
            "select \"a;set\"",
            "select $tag$ ; set x = 1 $tag$",
            "select $1; ",
            "select 1 -- ; set x = 1",
            "select 1 /* ; set x = 1 */",
            "select U&'d\\0061t; set'",
            "select a$b$ from t",
            "select 'a'\n'; set x = 1'",
            "select E'a'\n  'b\\'; set x = 1'",
        ] {
            assert_eq!(rejected(sql), None, "{sql}");
        }
    }

    #[test]
    fn unterminated_input_never_panics() {
        for sql in [
            "select '",
            "select E'\\",
            "select $a$",
            "/* /*",
            "select \"",
            "$",
            "U&",
        ] {
            let _ = check(sql);
        }
    }
}
