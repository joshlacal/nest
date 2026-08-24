use crate::{error::AppError, models::CatbirdSession};

pub const CIRCLE_MEMBER_SCOPE: &str = "space:blue.catbird.circle?authority=*&action=read&action=create&action=update&action=delete&collection=app.bsky.feed.post&collection=app.bsky.feed.like";
pub const CIRCLE_OWNER_SCOPE: &str = "space:blue.catbird.circle?authority=self&action=create&action=update&action=delete&manage=create&manage=update&manage=delete&collection=blue.catbird.circle.metadata";
pub const CIRCLE_PROTOCOL_REVISION: &str = "89deb9faca20e56fa2a262fe9746ed52bc1095ba";

pub fn require_circle_scopes(session: &CatbirdSession) -> Result<(), AppError> {
    if session.scopes.iter().any(|scope| scope == CIRCLE_MEMBER_SCOPE)
        && session.scopes.iter().any(|scope| scope == CIRCLE_OWNER_SCOPE)
    {
        Ok(())
    } else {
        Err(AppError::Unauthorized("Circle scopes require reauthorization".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_scope_constants_are_exact() {
        assert!(CIRCLE_MEMBER_SCOPE.starts_with("space:blue.catbird.circle?"));
        assert!(CIRCLE_OWNER_SCOPE.starts_with("space:blue.catbird.circle?"));
        assert_eq!(CIRCLE_PROTOCOL_REVISION.len(), 40);
    }
}
