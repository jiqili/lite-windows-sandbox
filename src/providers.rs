pub struct Provider {
    pub name: &'static str,
    pub origin: &'static str,
    pub path: &'static str,
    pub auth_header: &'static str,
    pub bearer: bool,
}

pub const SUPPORTED: &[Provider] = &[
    Provider {
        name: "openrouter",
        origin: "https://openrouter.ai",
        path: "/api/v1",
        auth_header: "authorization",
        bearer: true,
    },
    Provider {
        name: "openai",
        origin: "https://api.openai.com",
        path: "/v1",
        auth_header: "authorization",
        bearer: true,
    },
    Provider {
        name: "anthropic",
        origin: "https://api.anthropic.com",
        path: "",
        auth_header: "x-api-key",
        bearer: false,
    },
    Provider {
        name: "deepseek",
        origin: "https://api.deepseek.com",
        path: "",
        auth_header: "authorization",
        bearer: true,
    },
    Provider {
        name: "google",
        origin: "https://generativelanguage.googleapis.com",
        path: "/v1beta",
        auth_header: "x-goog-api-key",
        bearer: false,
    },
];

pub fn get(name: &str) -> Option<&'static Provider> {
    SUPPORTED.iter().find(|provider| provider.name == name)
}
