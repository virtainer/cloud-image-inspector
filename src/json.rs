//! A JSON value and writer: all the output side needs.

pub enum J {
    Null,
    Bool(bool),
    Int(i128),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

impl J {
    pub fn obj(pairs: Vec<(&str, J)>) -> J {
        J::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn str(s: impl Into<String>) -> J {
        J::Str(s.into())
    }

    pub fn opt_str(s: &Option<String>) -> J {
        s.as_ref().map(|s| J::Str(s.clone())).unwrap_or(J::Null)
    }

    pub fn strs(v: &[String]) -> J {
        J::Arr(v.iter().map(|s| J::Str(s.clone())).collect())
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, 0);
        s.push('\n');
        s
    }

    fn write(&self, out: &mut String, depth: usize) {
        let pad = |out: &mut String, d: usize| out.push_str(&"  ".repeat(d));
        match self {
            J::Null => out.push_str("null"),
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Int(i) => out.push_str(&i.to_string()),
            J::Str(s) => escape(s, out),
            J::Arr(v) if v.is_empty() => out.push_str("[]"),
            J::Arr(v) => {
                out.push_str("[\n");
                for (i, x) in v.iter().enumerate() {
                    pad(out, depth + 1);
                    x.write(out, depth + 1);
                    out.push_str(if i + 1 < v.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push(']');
            }
            J::Obj(v) if v.is_empty() => out.push_str("{}"),
            J::Obj(v) => {
                out.push_str("{\n");
                for (i, (k, x)) in v.iter().enumerate() {
                    pad(out, depth + 1);
                    escape(k, out);
                    out.push_str(": ");
                    x.write(out, depth + 1);
                    out.push_str(if i + 1 < v.len() { ",\n" } else { "\n" });
                }
                pad(out, depth);
                out.push('}');
            }
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}
