use regex::Regex;

pub struct PasswordPolicy {
    min_length: usize,
    max_length: usize,
    require_uppercase: bool,
    require_lowercase: bool,
    require_digit: bool,
    require_special: bool,
}

impl PasswordPolicy {
    pub fn new(
        min_length: usize,
        max_length: usize,
        require_uppercase: bool,
        require_lowercase: bool,
        require_digit: bool,
        require_special: bool,
    ) -> Self {
        Self {
            min_length,
            max_length,
            require_uppercase,
            require_lowercase,
            require_digit,
            require_special,
        }
    }

    pub fn validate(&self, password: &str) -> Result<(), String> {
        if password.len() < self.min_length {
            return Err(format!("Password must be at least {} characters long.", self.min_length));
        }
        if password.len() > self.max_length {
            return Err(format!("Password must be no more than {} characters long.", self.max_length));
        }
        if self.require_uppercase && !Regex::new(r"[A-Z]").unwrap().is_match(password) {
            return Err("Password must contain at least one uppercase letter.".to_string());
        }
        if self.require_lowercase && !Regex::new(r"[a-z]").unwrap().is_match(password) {
            return Err("Password must contain at least one lowercase letter.".to_string());
        }
        if self.require_digit && !Regex::new(r"\d").unwrap().is_match(password) {
            return Err("Password must contain at least one digit.".to_string());
        }
        if self.require_special && !Regex::new(r"[!@#$%^&*(),.?\":{}|<>]").unwrap().is_match(password) {
            return Err("Password must contain at least one special character.".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_policy() {
        let policy = PasswordPolicy::new(8, 32, true, true, true, true);

        assert!(policy.validate("Valid1Password!").is_ok());
        assert!(policy.validate("short").is_err());
        assert!(policy.validate("nouppercase1!").is_err());
        assert!(policy.validate("NOLOWERCASE1!").is_err());
        assert!(policy.validate("NoDigits!").is_err());
        assert!(policy.validate("NoSpecial1").is_err());
    }
}