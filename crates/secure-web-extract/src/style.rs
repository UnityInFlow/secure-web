//! Inline-style hidden-content detection (`docs/security-policy.md` §3, threat T3).
//!
//! Heuristic by design: only inline `style` attributes are inspected (no stylesheet cascade).
//! Anything flagged here is removed from display but still reaches `security_text`, so a false
//! positive costs readability, never security.

/// Why an inline style hides its element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StyleHidden {
    /// `display:none`, `visibility:hidden|collapse`, `opacity:0`, `color:transparent`.
    Css,
    /// `font-size:0`, or zero `width`/`height`/`max-*` with `overflow:hidden`, or a zero clip.
    ZeroSize,
    /// Pushed far off screen (`left:-9999px`, `text-indent:-9999px`, …).
    Offscreen,
}

/// Longest `style` attribute inspected; longer values are only scanned up to this many bytes.
const MAX_STYLE_BYTES: usize = 4096;

/// Classify an inline `style` attribute.
pub(crate) fn hidden_by_style(style: &str) -> Option<StyleHidden> {
    let mut end = style.len().min(MAX_STYLE_BYTES);
    while !style.is_char_boundary(end) {
        end -= 1;
    }
    let style = style[..end].to_ascii_lowercase();
    let mut zero_box = false;
    let mut overflow_hidden = false;
    let mut result = None;
    for declaration in style.split(';') {
        let Some((property, value)) = declaration.split_once(':') else {
            continue;
        };
        let property = property.trim();
        let value = value.replace("!important", "");
        let value = value.trim();
        match property {
            "display" if value == "none" => return Some(StyleHidden::Css),
            "visibility" if value == "hidden" || value == "collapse" => {
                return Some(StyleHidden::Css)
            }
            "opacity" if is_zero(value) => return Some(StyleHidden::Css),
            "color" if value == "transparent" => return Some(StyleHidden::Css),
            "font-size" if is_zero(value) => result = result.or(Some(StyleHidden::ZeroSize)),
            "width" | "height" | "max-width" | "max-height" if is_zero(value) => zero_box = true,
            "overflow" | "overflow-x" | "overflow-y" if value == "hidden" || value == "clip" => {
                overflow_hidden = true
            }
            "clip" if is_zero_rect(value) => result = result.or(Some(StyleHidden::ZeroSize)),
            "clip-path" if value.starts_with("inset(50%") || value.starts_with("circle(0") => {
                result = result.or(Some(StyleHidden::ZeroSize))
            }
            "left" | "right" | "top" | "bottom" | "text-indent" | "margin-left" | "margin-top"
            | "inset"
                if is_far_offscreen(value) =>
            {
                result = result.or(Some(StyleHidden::Offscreen))
            }
            "transform" if is_far_translate(value) => {
                result = result.or(Some(StyleHidden::Offscreen))
            }
            _ => {}
        }
    }
    if zero_box && overflow_hidden {
        result = result.or(Some(StyleHidden::ZeroSize));
    }
    result
}

/// `0`, `0px`, `0.0em`, `.0`, `0%`, … (any unit).
fn is_zero(value: &str) -> bool {
    let number = value.trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == '%');
    !number.is_empty()
        && number.bytes().any(|b| b.is_ascii_digit())
        && number.bytes().all(|b| b == b'0' || b == b'.')
}

fn is_zero_rect(value: &str) -> bool {
    value
        .strip_prefix("rect(")
        .and_then(|rest| rest.strip_suffix(')'))
        .is_some_and(|inner| {
            inner
                .split([',', ' '])
                .filter(|part| !part.is_empty())
                .all(|part| is_zero(part.trim()))
        })
}

/// A negative length whose magnitude puts the element off any screen.
fn is_far_offscreen(value: &str) -> bool {
    value
        .split_whitespace()
        .any(|part| negative_magnitude(part).is_some_and(|(n, unit)| far(n, unit)))
}

fn is_far_translate(value: &str) -> bool {
    let Some(start) = value.find("translate") else {
        return false;
    };
    let Some(open) = value[start..].find('(') else {
        return false;
    };
    value[start + open + 1..]
        .split([',', ')', ' '])
        .any(|part| negative_magnitude(part.trim()).is_some_and(|(n, unit)| far(n, unit)))
}

fn far(magnitude: f64, unit: &str) -> bool {
    match unit {
        "px" | "pt" | "" => magnitude >= 500.0,
        "em" | "rem" | "ch" | "ex" => magnitude >= 50.0,
        "%" | "vw" | "vh" | "vmin" | "vmax" => magnitude >= 100.0,
        "in" | "cm" => magnitude >= 5.0,
        "mm" => magnitude >= 50.0,
        _ => false,
    }
}

/// `-9999px` → `(9999.0, "px")`.
fn negative_magnitude(part: &str) -> Option<(f64, &str)> {
    let rest = part.strip_prefix('-')?;
    let split = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len());
    let (number, unit) = rest.split_at(split);
    let magnitude: f64 = number.parse().ok()?;
    Some((magnitude, unit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_css_hiding() {
        for style in [
            "display:none",
            "DISPLAY : NONE !important",
            "color:red; visibility: hidden",
            "opacity:0",
            "opacity: 0.0",
            "color: transparent",
        ] {
            assert_eq!(hidden_by_style(style), Some(StyleHidden::Css), "{style}");
        }
    }

    #[test]
    fn detects_zero_size_and_offscreen() {
        for style in [
            "font-size:0",
            "font-size:0px",
            "width:0;height:0;overflow:hidden",
            "clip: rect(0 0 0 0)",
            "clip-path: inset(50%)",
        ] {
            assert_eq!(
                hidden_by_style(style),
                Some(StyleHidden::ZeroSize),
                "{style}"
            );
        }
        for style in [
            "position:absolute;left:-9999px",
            "text-indent:-10000px",
            "top: -100vh",
            "transform: translateX(-9999px)",
        ] {
            assert_eq!(
                hidden_by_style(style),
                Some(StyleHidden::Offscreen),
                "{style}"
            );
        }
    }

    #[test]
    fn ordinary_styles_are_visible() {
        for style in [
            "",
            "color:red",
            "margin-left:-4px",
            "width:0",
            "opacity:0.5",
            "font-size:10px",
            "display:block",
            "left:-10%",
        ] {
            assert_eq!(hidden_by_style(style), None, "{style}");
        }
    }
}
