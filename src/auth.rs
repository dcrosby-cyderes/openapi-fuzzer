use crate::Header;
use anyhow::{anyhow, Result};
use std::process::Command;
use std::{str::FromStr, time::Instant};

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ApiAuth {
    Bearer,
}

impl FromStr for ApiAuth {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bearer" => Ok(Self::Bearer),
            t => Err(anyhow!("Unsupported type {}", t)),
        }
    }
}

impl ToString for ApiAuth {
    fn to_string(&self) -> String {
        match self {
            Self::Bearer => String::from("Bearer"),
        }
    }
}

#[derive(Debug, Clone)]
enum LifeSpan {
    Indefinite,
    SingleUse,
    Seconds(i64),
}

impl From<i64> for LifeSpan {
    fn from(value: i64) -> Self {
        match value {
            v if v < 0 => Self::Indefinite,
            v if v == 0 => Self::SingleUse,
            v => Self::Seconds(v),
        }
    }
}

#[derive(Debug, Clone)]
struct AuthToken {
    token: String,
    lifespan: LifeSpan,
    last_refreshed: Instant,
}

#[derive(Debug, Clone)]
pub struct Auth {
    auth_type: ApiAuth,
    token: Option<AuthToken>,
    refresh_cmd: String,
}

impl Auth {
    pub(crate) fn new(refresh_cmd: String, auth_type: ApiAuth) -> Self {
        Self {
            auth_type,
            token: None,
            refresh_cmd,
        }
    }

    pub(crate) fn access_token(&mut self) -> Result<Option<Header>> {
        if !self.refresh_cmd.is_empty() {
            match self.get_token() {
                Ok(t) => {
                    let auth_type = self.auth_type.to_string();
                    let header = Header(
                        String::from("Authorization"),
                        format!("{} {}", auth_type, t),
                    );
                    Ok(Some(header))
                }
                Err(e) => Err(e),
            }
        } else {
            Ok(None)
        }
    }

    fn get_token(&mut self) -> Result<String> {
        let token = match self.token.clone() {
            None => Self::refresh_token(&self.refresh_cmd)?,
            Some(t) => match t.lifespan {
                LifeSpan::Indefinite => t,
                LifeSpan::SingleUse => Self::refresh_token(&self.refresh_cmd)?,
                LifeSpan::Seconds(s) => {
                    if t.last_refreshed.elapsed().as_secs() > (s as u64 / 2) {
                        Self::refresh_token(&self.refresh_cmd)?
                    } else {
                        t
                    }
                }
            },
        };
        let token_string = token.token.clone();
        self.token = Some(token);
        Ok(token_string)
    }

    fn refresh_token(refresh_cmd: &str) -> Result<AuthToken> {
        let mut cmd = Command::new(refresh_cmd);
        let output = cmd.output()?;
        let new_token_raw = String::from_utf8(output.stdout)?;
        let token_info: Vec<&str> = new_token_raw.split_whitespace().collect();
        if token_info.len() != 2 {
            Err(anyhow!("Invalid token command output"))
        } else {
            let (token, lifetime) = (token_info[0].to_string(), token_info[1].parse::<i64>()?);
            Ok(AuthToken {
                token,
                lifespan: lifetime.into(),
                last_refreshed: Instant::now(),
            })
        }
    }
}
