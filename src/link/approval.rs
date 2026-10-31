use std::fmt;
use std::future::Future;

use crate::config::GatewayName;
use crate::ipc::{Request, RequestError, Response};
use crate::link::{Confirmation, LinkError};
use crate::uri::LaunchRequest;

#[derive(Debug)]
pub enum ApprovalError {
    Request(RequestError),
    MissingSelector,
    UnnamedGateway,
    NotEchoed,
    Unasked(String),
    Denied(GatewayName),
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request(error) => error.fmt(f),
            Self::MissingSelector => f.write_str("the launch has no gateway selector"),
            Self::UnnamedGateway => {
                f.write_str("the agent asked to confirm a gateway the link does not name")
            }
            Self::NotEchoed => f.write_str(
                "the agent asked to confirm another gateway than the link names; nothing was \
                 stored",
            ),
            Self::Unasked(reason) => f.write_str(reason),
            Self::Denied(profile) => LinkError::Denied(profile.clone()).fmt(f),
        }
    }
}

impl std::error::Error for ApprovalError {}

pub async fn settle<S, R, A, Q>(
    launch: &LaunchRequest,
    reply: Response,
    send: S,
    ask: A,
) -> Result<Response, ApprovalError>
where
    S: Fn(Request) -> R,
    R: Future<Output = Result<Response, RequestError>>,
    A: FnOnce(Confirmation) -> Q,
    Q: Future<Output = Result<bool, String>>,
{
    let lines = match &reply {
        Response::Ok(lines) => lines.as_slice(),
        Response::Error(_) => &[],
    };
    let Some(token) = crate::ipc::confirm_token(lines) else {
        return Ok(reply);
    };
    let deny = async |error| match send(Request::Deny(token)).await {
        Ok(_) => Err(error),
        Err(failure) => Err(ApprovalError::Request(failure)),
    };
    let Some(profile) = launch.proposed_profile() else {
        return deny(ApprovalError::MissingSelector).await;
    };
    let Some(gateway) = launch.gateway.clone() else {
        return deny(ApprovalError::UnnamedGateway).await;
    };
    let confirmation = Confirmation {
        route: launch.route.unwrap_or_default(),
        profile: profile.clone(),
        gateway,
        portal: launch.portal.clone(),
    };
    if !confirmation.echoed_by(lines) {
        return deny(ApprovalError::NotEchoed).await;
    }
    match ask(confirmation).await {
        Ok(true) => send(Request::Approve(token))
            .await
            .map_err(ApprovalError::Request),
        Ok(false) => deny(ApprovalError::Denied(profile)).await,
        Err(reason) => deny(ApprovalError::Unasked(reason)).await,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::ipc::{self, ConfirmToken};
    use crate::proxy::Route;

    const TOKEN: &str = "00112233445566778899aabbccddeeff";
    const LINK: &str = "gateinto://connect?profile=newco&gateway=proxy.newco.example\
                        &portal=https%3A%2F%2Fportal.newco.example%2Fhome";

    fn token() -> ConfirmToken {
        TOKEN.parse().unwrap()
    }

    fn launch(uri: &str) -> LaunchRequest {
        uri.parse().unwrap()
    }

    fn confirmation(launch: &LaunchRequest) -> Confirmation {
        Confirmation {
            route: launch.route.unwrap_or_default(),
            profile: launch.proposed_profile().unwrap(),
            gateway: launch.gateway.clone().unwrap(),
            portal: launch.portal.clone(),
        }
    }

    fn asking(launch: &LaunchRequest) -> Response {
        let mut lines = confirmation(launch).echo();
        lines.push(ipc::confirm_line(&token()));
        Response::Ok(lines)
    }

    fn launched() -> Response {
        Response::Ok(vec!["session: 1".to_owned()])
    }

    struct Agent {
        sent: RefCell<Vec<Request>>,
        fails: bool,
    }

    impl Agent {
        fn new() -> Self {
            Self {
                sent: RefCell::new(Vec::new()),
                fails: false,
            }
        }

        fn failing() -> Self {
            Self {
                fails: true,
                ..Self::new()
            }
        }

        fn send(&self) -> impl Fn(Request) -> std::future::Ready<Result<Response, RequestError>> {
            |request| {
                self.sent.borrow_mut().push(request);
                std::future::ready(if self.fails {
                    Err(RequestError::Closed)
                } else {
                    Ok(launched())
                })
            }
        }

        fn sent(&self) -> Vec<Request> {
            self.sent.borrow().clone()
        }
    }

    fn answer(
        answer: Result<bool, String>,
    ) -> impl FnOnce(Confirmation) -> std::future::Ready<Result<bool, String>> {
        move |_| std::future::ready(answer)
    }

    async fn settle_link(
        agent: &Agent,
        ask: impl FnOnce(Confirmation) -> std::future::Ready<Result<bool, String>>,
    ) -> Result<Response, ApprovalError> {
        let link = launch(LINK);
        settle(&link, asking(&link), agent.send(), ask).await
    }

    fn unasked(_: Confirmation) -> std::future::Ready<Result<bool, String>> {
        panic!("asked")
    }

    #[tokio::test]
    async fn a_reply_without_a_confirm_token_is_returned_unasked() {
        let agent = Agent::new();
        for reply in [launched(), Response::Error("refused".to_owned())] {
            let settled = settle(&launch(LINK), reply.clone(), agent.send(), unasked).await;
            assert_eq!(settled.unwrap(), reply);
        }
        assert!(agent.sent().is_empty());
    }

    #[tokio::test]
    async fn the_asked_confirmation_is_the_one_the_link_names() {
        let link = launch(&format!("{LINK}&route=mixed"));
        let agent = Agent::new();
        let asked = RefCell::new(None);
        let ask = |confirmation| {
            *asked.borrow_mut() = Some(confirmation);
            std::future::ready(Ok(true))
        };
        settle(&link, asking(&link), agent.send(), ask)
            .await
            .unwrap();
        let asked = asked.into_inner().unwrap();
        assert_eq!(asked, confirmation(&link));
        assert_eq!(asked.route, Route::Mixed);
    }

    #[tokio::test]
    async fn approval_sends_approve_and_returns_its_reply() {
        let agent = Agent::new();
        let settled = settle_link(&agent, answer(Ok(true))).await;
        assert_eq!(settled.unwrap(), launched());
        assert_eq!(agent.sent(), [Request::Approve(token())]);
    }

    #[tokio::test]
    async fn a_refusal_denies_and_says_nothing_was_stored() {
        let agent = Agent::new();
        let error = settle_link(&agent, answer(Ok(false))).await.unwrap_err();
        assert!(matches!(&error, ApprovalError::Denied(name) if name.as_str() == "newco"));
        assert_eq!(
            error.to_string(),
            LinkError::Denied("newco".parse().unwrap()).to_string()
        );
        assert_eq!(agent.sent(), [Request::Deny(token())]);
    }

    #[tokio::test]
    async fn a_failure_to_ask_denies_and_keeps_the_reason() {
        let agent = Agent::new();
        let failed = answer(Err("no desktop".to_owned()));
        let error = settle_link(&agent, failed).await.unwrap_err();
        assert_eq!(error.to_string(), "no desktop");
        assert_eq!(agent.sent(), [Request::Deny(token())]);
    }

    #[tokio::test]
    async fn a_link_without_a_gateway_address_denies_unasked() {
        let link = launch("gateinto://connect?profile=newco");
        let reply = Response::Ok(vec![ipc::confirm_line(&token())]);
        let agent = Agent::new();
        let error = settle(&link, reply, agent.send(), unasked)
            .await
            .unwrap_err();
        assert!(matches!(error, ApprovalError::UnnamedGateway), "{error}");
        assert_eq!(
            error.to_string(),
            "the agent asked to confirm a gateway the link does not name"
        );
        assert_eq!(agent.sent(), [Request::Deny(token())]);
    }

    #[tokio::test]
    async fn a_launch_without_a_selector_denies_unasked() {
        let link = LaunchRequest {
            profile: None,
            gateway: None,
            ..launch(LINK)
        };
        let agent = Agent::new();
        let error = settle(&link, asking(&launch(LINK)), agent.send(), unasked)
            .await
            .unwrap_err();
        assert!(matches!(error, ApprovalError::MissingSelector), "{error}");
        assert_eq!(error.to_string(), "the launch has no gateway selector");
        assert_eq!(agent.sent(), [Request::Deny(token())]);
    }

    #[tokio::test]
    async fn an_echo_of_another_gateway_denies_unasked() {
        let other = launch(&LINK.replace("proxy.newco", "proxy.other"));
        let gateway = launch(&format!("{LINK}&route=gateway"));
        for reply in [
            asking(&other),
            asking(&gateway),
            Response::Ok(vec![ipc::confirm_line(&token())]),
        ] {
            let agent = Agent::new();
            let error = settle(&launch(LINK), reply, agent.send(), unasked)
                .await
                .unwrap_err();
            assert!(matches!(error, ApprovalError::NotEchoed), "{error}");
            assert_eq!(
                error.to_string(),
                "the agent asked to confirm another gateway than the link names; nothing was \
                 stored"
            );
            assert_eq!(agent.sent(), [Request::Deny(token())]);
        }
    }

    #[tokio::test]
    async fn a_failed_denial_reports_the_agent_error() {
        let agent = Agent::failing();
        let error = settle_link(&agent, answer(Ok(false))).await.unwrap_err();
        assert!(
            matches!(error, ApprovalError::Request(RequestError::Closed)),
            "{error}"
        );
        assert_eq!(error.to_string(), RequestError::Closed.to_string());
        assert_eq!(agent.sent(), [Request::Deny(token())]);
    }

    #[tokio::test]
    async fn a_failed_approval_reports_the_agent_error() {
        let agent = Agent::failing();
        let error = settle_link(&agent, answer(Ok(true))).await.unwrap_err();
        assert!(
            matches!(error, ApprovalError::Request(RequestError::Closed)),
            "{error}"
        );
        assert_eq!(agent.sent(), [Request::Approve(token())]);
    }
}
