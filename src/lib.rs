#![forbid(unsafe_code)]

//! Identify by username: a name presented in the clear is the claim.
//!
//! The oldest credential there is: an FTP `USER`, a SASL PLAIN authcid, an
//! SMTP `AUTH LOGIN` name, a SQL login, the user half of an HTTP Basic
//! credential. The carrier that speaks the protocol promotes the name onto
//! the arrival, and this identifier presents it under
//! [`xcore::mechanism::username`], passed and proving nothing. The mechanism
//! is a username *without* a proof; where the transport was handed a password
//! with it, that password rides on [`Presented::proof`] for the second gate —
//! `authenticate/password`, `ldap`, `pam` or `windows` — and never reaches
//! the record, the evidence or a log line.
//!
//! What this reads, in this order, the first that is there standing:
//!
//! ```text
//! username                    the name, in the shared vocabulary      the claim
//! password                    what came with it, where anything did   proof password
//! http.header.authorization   Basic <base64>: the user half           proof basic.credential
//! ```
//!
//! A carrier with its own words for the pair — `ftp.user` and `ftp.pass` — is
//! read by building the identifier with [`Username::from_properties`]. A
//! Basic credential is carried whole as `basic.credential`, exactly as it
//! arrived, because that is what `authenticate/basic` decodes; any other
//! `Authorization` scheme is somebody else's and presents nothing here.
//!
//! Only a pushed Stream has somebody who logged in. On a scheduled pickup the
//! username in play was Xmip's own and says nothing about the source.
//!
//! Evidence this technology writes: `username.source`, the property the name
//! was read from; and `principal.user`, the name in the capability's canonical
//! form, where the presented name is a user principal name — `user@domain` or
//! `DOMAIN\user` (ADR-0054). A bare `jane` is not one, and nothing is added.

use context::property::HTTP_AUTHORIZATION;
use identify::authorization;
use identify::evidence;
use identify::{IdentifyError, Presented, StreamArrival, TransportIdentifier, UserPrincipalName};
use xcore::{Arriving, Mechanism};

/// The shared property a carrier promotes a username under.
pub const USERNAME: &str = "username";
/// The shared property a carrier promotes the password under, where it was
/// handed one.
pub const PASSWORD: &str = "password";
/// The evidence name the property the name was read from rides under.
pub const SOURCE: &str = "username.source";

/// Reads a username, and the password where one came with it.
#[derive(Clone, Debug)]
pub struct Username {
    username: String,
    password: String,
}

impl Username {
    /// Read the pair from a carrier's own properties, `ftp.user` and
    /// `ftp.pass` say, instead of the shared [`USERNAME`] and [`PASSWORD`].
    ///
    /// # Errors
    ///
    /// Where either name is empty, or the two are the same property: the
    /// password would be presented as the name, and onto the record.
    pub fn from_properties(username: &str, password: &str) -> Result<Self, IdentifyError> {
        let (username, password) = (username.trim(), password.trim());
        if username.is_empty() || password.is_empty() {
            return Err(IdentifyError::new(
                "the username and password properties to read both need a name",
            ));
        }
        if username == password {
            return Err(IdentifyError::new(format!(
                "{username} cannot be both the username and the password property"
            )));
        }

        Ok(Self {
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    fn promoted(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        let password = arrival.property(&self.password);
        let Some(name) = arrival.property(&self.username) else {
            return match password {
                Some(_) => Err(IdentifyError::new(format!(
                    "the carrier promoted {} without {}",
                    self.password, self.username
                ))),
                None => Ok(None),
            };
        };

        let name = name.trim();
        if name.is_empty() {
            return Err(IdentifyError::new(format!(
                "the carrier promoted {} and left it empty",
                self.username
            )));
        }

        let claim = named(
            Presented::passed(xcore::mechanism::username(), name)
                .with_evidence(SOURCE, &self.username),
        );
        Ok(Some(match password {
            Some(password) => claim.with_proof(evidence::PASSWORD, password),
            None => claim,
        }))
    }
}

impl Default for Username {
    /// Reads [`USERNAME`] and [`PASSWORD`].
    fn default() -> Self {
        Self {
            username: USERNAME.to_string(),
            password: PASSWORD.to_string(),
        }
    }
}

/// The user half of an `Authorization: Basic` value, with the credential as
/// proof; `None` for any other scheme.
fn basic(authorization: &str) -> Result<Option<Presented>, IdentifyError> {
    let Some(credential) = authorization::under(authorization, "basic") else {
        return Ok(None);
    };
    let (user, _) = authorization::basic(credential)?;

    Ok(Some(
        named(
            Presented::passed(xcore::mechanism::username(), user.as_str())
                .with_evidence(SOURCE, HTTP_AUTHORIZATION),
        )
        .with_proof(evidence::BASIC_CREDENTIAL, credential),
    ))
}

/// The claim, with its value beside it as `principal.user` in canonical form
/// where that value is a user principal name (ADR-0054); otherwise as it was.
fn named(claim: Presented) -> Presented {
    match UserPrincipalName::parse(&claim.value) {
        Some(name) => claim.with_evidence(evidence::PRINCIPAL_USER, name.to_string()),
        None => claim,
    }
}

impl TransportIdentifier for Username {
    fn mechanism(&self) -> Mechanism {
        xcore::mechanism::username()
    }

    fn identify(&self, arrival: &StreamArrival<'_>) -> Result<Option<Presented>, IdentifyError> {
        if arrival.arriving() != Arriving::Pushed {
            return Ok(None);
        }

        if let Some(claim) = self.promoted(arrival)? {
            return Ok(Some(claim));
        }

        arrival.property(HTTP_AUTHORIZATION).map_or(Ok(None), basic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stream::Stream;
    use xcore::{Established, Layer, StreamId};

    fn stream() -> Stream {
        Stream::new(StreamId::new(1), b"<order/>".to_vec(), None)
    }

    fn facts(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn a_username_without_a_password_is_a_claim_with_nothing_behind_it() {
        let stream = stream();
        let facts = facts(&[(USERNAME, "partner-x")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "ftp://xmip/in", &facts);

        let claim = Username::default()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.mechanism.name(), "username");
        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.established, Established::Passed);
        assert_eq!(claim.layer(), Layer::Transport);
        assert_eq!(claim.proof(evidence::PASSWORD), None);
        assert_eq!(
            claim.evidence,
            vec![(SOURCE.to_string(), USERNAME.to_string())]
        );
    }

    #[test]
    fn the_password_rides_as_proof_and_reaches_neither_the_record_nor_a_log_line() {
        let stream = stream();
        let facts = facts(&[("ftp.user", "partner-x"), ("ftp.pass", "s3cr3t")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "ftp://xmip/in", &facts);

        let claim = Username::from_properties("ftp.user", "ftp.pass")
            .expect("two names")
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(claim.proof(evidence::PASSWORD), Some("s3cr3t"));
        assert!(claim.evidence.iter().all(|(_, value)| value != "s3cr3t"));
        assert!(!format!("{claim:?}").contains("s3cr3t"));
    }

    #[test]
    fn a_basic_authorization_presents_its_user_and_carries_the_credential_whole() {
        let stream = stream();
        let facts = facts(&[(HTTP_AUTHORIZATION, "basic cGFydG5lci14OnMzY3IzdA==")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);

        let claim = Username::default()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "partner-x");
        assert_eq!(
            claim.proof(evidence::BASIC_CREDENTIAL),
            Some("cGFydG5lci14OnMzY3IzdA==")
        );
        assert_eq!(claim.proof(evidence::PASSWORD), None);
    }

    #[test]
    fn an_arrival_nobody_logged_in_on_presents_nothing() {
        let stream = stream();
        let facts = facts(&[(HTTP_AUTHORIZATION, "Bearer mF_9.B5f-4.1JqM")]);
        let bearer = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &facts);
        let bare = StreamArrival::new(&stream, Arriving::Pushed, "file:///in/x", &[]);

        assert!(
            Username::default()
                .identify(&bearer)
                .expect("read")
                .is_none()
        );
        assert!(Username::default().identify(&bare).expect("read").is_none());
    }

    #[test]
    fn a_password_without_a_username_and_a_credential_that_does_not_decode_are_errors() {
        let stream = stream();
        let orphan = facts(&[(PASSWORD, "s3cr3t")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "ftp://xmip/in", &orphan);
        let failure = Username::default().identify(&arrival).expect_err("orphan");
        assert_eq!(
            failure.to_string(),
            "the carrier promoted password without username"
        );

        let garbled = facts(&[(HTTP_AUTHORIZATION, "Basic not*base64")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &garbled);
        let failure = Username::default().identify(&arrival).expect_err("garbled");
        assert_eq!(failure.to_string(), "the Basic credential is not base64");
    }

    #[test]
    fn one_property_cannot_be_both_the_name_and_the_password() {
        let failure = Username::from_properties("login", "login").expect_err("the same");

        assert!(failure.message.contains("cannot be both"), "{failure}");
        assert!(Username::from_properties("login", " ").is_err());
    }

    #[test]
    fn a_user_principal_name_is_written_beside_the_value_in_canonical_form() {
        let stream = stream();
        let modern = facts(&[(USERNAME, "Jane@Partner-X.Example")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "ftp://xmip/in", &modern);
        let claim = Username::default()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "Jane@Partner-X.Example", "the value stands");
        assert!(claim.evidence.contains(&(
            evidence::PRINCIPAL_USER.to_string(),
            "Jane@partner-x.example".to_string()
        )));

        // `PARTNERX\jane:s3cr3t`, the down-level form in a Basic credential.
        let older = facts(&[(HTTP_AUTHORIZATION, "Basic UEFSVE5FUlhcamFuZTpzM2NyM3Q=")]);
        let arrival = StreamArrival::new(&stream, Arriving::Pushed, "https://xmip/in", &older);
        let claim = Username::default()
            .identify(&arrival)
            .expect("read")
            .expect("a claim");

        assert_eq!(claim.value, "PARTNERX\\jane");
        assert!(claim.evidence.contains(&(
            evidence::PRINCIPAL_USER.to_string(),
            "jane@partnerx".to_string()
        )));
    }

    #[test]
    fn a_name_that_is_not_a_principal_name_gains_no_principal_evidence() {
        let stream = stream();

        for name in ["jane", "jane@", "jane@bad domain"] {
            let facts = facts(&[(USERNAME, name)]);
            let arrival = StreamArrival::new(&stream, Arriving::Pushed, "ftp://xmip/in", &facts);
            let claim = Username::default()
                .identify(&arrival)
                .expect("read")
                .expect("a claim");

            assert!(
                claim
                    .evidence
                    .iter()
                    .all(|(evidence, _)| evidence != evidence::PRINCIPAL_USER),
                "{name}"
            );
        }
    }

    #[test]
    fn a_scheduled_pickup_logged_in_as_xmip_and_says_nothing_about_the_source() {
        let stream = stream();
        let facts = facts(&[(USERNAME, "xmip-fetch"), (PASSWORD, "own")]);
        let arrival = StreamArrival::new(&stream, Arriving::Scheduled, "ftp://partner/out", &facts);

        assert!(
            Username::default()
                .identify(&arrival)
                .expect("read")
                .is_none()
        );
    }
}
