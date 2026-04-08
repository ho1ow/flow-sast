    """
    phases/_shared/source_catalog.py
    ──────────────────────────────────
    Single source of truth cho TAINT_SOURCES và TRUSTED_SOURCES.

    Import ở đây để tránh duplicate giữa:
    - phases/1_catalog/semgrep_runner.py    (taint source patterns)
    - phases/1_catalog/gitnexus_runner.py   (custom rule generation)
    - phases/2_connect/triage.py            (source match scoring bonus)
    - phases/2_connect/gitnexus_fp_filter.py (trusted source exclusion)
    """

    from __future__ import annotations

    from typing import Dict, List


    # ── HTTP / User-controlled sources per stack ─────────────────────────────────
    # Format: Semgrep pattern strings, dùng được cho cả rule generation và triage

    TAINT_SOURCES: Dict[str, List[str]] = {
        "php": [
            "$_GET",
            "$_POST",
            "$_FILES",
            "$_COOKIE",
            "$_REQUEST",
            "$_SERVER['HTTP_']",
            "$_SERVER['PHP_SELF']",
            "$_SERVER['REQUEST_URI']",
            "$_SERVER['QUERY_STRING']",
            "$HTTP_GET_VARS",
            "$HTTP_POST_VARS",
            # PHP input stream
            "php://input",
            # Common framework helpers
            "request()->input(...)",
            "request()->get(...)",
            "request()->post(...)",
            "request()->file(...)",
            "request()->header(...)",
            "request()->cookie(...)",
            "Input::get(...)",
            "Input::all()",
        ],
        "python": [
            # Flask
            "request.args.get(...)",
            "request.args[...]",
            "request.form.get(...)",
            "request.form[...]",
            "request.json",
            "request.get_json()",
            "request.data",
            "request.files",
            "request.headers.get(...)",
            "request.cookies.get(...)",
            "request.values.get(...)",
            "request.environ.get(...)",
            # Django
            "request.GET.get(...)",
            "request.POST.get(...)",
            "request.FILES",
            "request.COOKIES",
            "request.META",
            "request.body",
            "request.data",  # DRF
            # FastAPI
            "Query(...)",
            "Body(...)",
            "Form(...)",
            "File(...)",
            "Header(...)",
            "Cookie(...)",
            "Path(...)",
        ],
        "node": [
            "req.body",
            "req.query",
            "req.params",
            "req.headers",
            "req.cookies",
            "req.files",
            "req.file",
            "request.body",
            "request.query",
            "request.params",
            "ctx.request.body",   # Koa
            "ctx.query",
            "ctx.params",
            "event.body",         # Lambda
            "event.queryStringParameters",
            "event.pathParameters",
            "event.headers",
        ],
        "java": [
            "request.getParameter(...)",
            "request.getParameterValues(...)",
            "request.getHeader(...)",
            "request.getCookies()",
            "request.getInputStream()",
            "request.getReader()",
            # Spring MVC annotations (patterns)
            "@RequestParam",
            "@RequestBody",
            "@PathVariable",
            "@RequestHeader",
            "@CookieValue",
            "@ModelAttribute",
        ],
        "go": [
            "r.URL.Query().Get(...)",
            "r.FormValue(...)",
            "r.PostFormValue(...)",
            "r.Header.Get(...)",
            "r.Cookie(...)",
            "r.Body",
            "c.Param(...)",     # Gin
            "c.Query(...)",
            "c.PostForm(...)",
            "c.GetHeader(...)",
            "c.BindJSON(...)",
        ],
        "ruby": [
            "params[...]",
            "params.require(...)",
            "request.body",
            "request.raw_post",
            "cookies[...]",
            "request.headers[...]",
            "request.env[...]",
        ],
        "csharp": [
            # ASP.NET Core MVC / Razor Pages
            "Request.Query[...]",
            "Request.Form[...]",
            "Request.Headers[...]",
            "Request.Cookies[...]",
            "Request.RouteValues[...]",
            "Request.Body",
            "Request.QueryString",
            # Action parameter binding (annotations as source markers)
            "[FromQuery]",
            "[FromBody]",
            "[FromRoute]",
            "[FromHeader]",
            "[FromForm]",
            # HttpContext
            "HttpContext.Request.Query[...]",
            "HttpContext.Request.Form[...]",
            "HttpContext.Request.Headers[...]",
            # Old ASP.NET WebForms / WebAPI
            "HttpRequest.QueryString[...]",
            "HttpRequest.Form[...]",
            "HttpRequest.Params[...]",
            "Request[...]",
            "Request.Params[...]",
            # Minimal API
            "app.MapGet",
            "app.MapPost",
        ],
    }


    # ── Trusted / Non-user-controlled sources (exclude from taint) ───────────────
    # Nếu source matching pattern này → NOT user-controlled → low FP risk

    TRUSTED_SOURCES: List[str] = [
        # Auth user object (server-controlled)
        "auth()->id()",
        "auth()->user()",
        "Auth::id()",
        "Auth::user()",
        "current_user.id",
        "current_user.email",
        "request.user.id",
        "request.user.pk",
        "g.user",
        "g.current_user",
        # Session (server-set)
        "session()->get(",
        "session[",
        "request.session[",
        "Session::get(",
        # Config / environment
        "config(",
        "env(",
        "Config::get(",
        "os.environ.get(",
        "process.env.",
        # Cache (server-set)
        "Cache::get(",
        "cache.get(",
        "Redis::get(",
        "redis.get(",
        # Constants
        "true", "false", "null", "None", "True", "False",
        # DB lookups by server-controlled PK (not user param)
        "Auth::user()->id",
        "current_user()->id",
    ]


    # ── Test file path patterns (FP — should reduce severity) ────────────────────

    TEST_FILE_PATTERNS: List[str] = [
        "/test/", "/tests/", "\\test\\", "\\tests\\",
        "/spec/", "/specs/", "\\spec\\",
        "/fixture/", "/fixtures/", "\\fixture\\",
        "/mock/", "/mocks/", "\\mock\\",
        "/stub/", "/stubs/", "\\stub\\",
        "/migration/", "/migrations/", "\\migration\\",
        "/seeder/", "/seeders/", "\\seeder\\",
        "/factory/", "/factories/", "\\factory\\",
        "Test.php", "Spec.php", "TestCase.php",
        "_test.go", "_test.py",
        ".test.js", ".test.ts",
        ".spec.js", ".spec.ts",
        "_spec.rb",
        # C# test patterns
        "Tests.cs", "Test.cs", "Spec.cs",
        "/UnitTests/", "/IntegrationTests/", "/TestHelpers/",
    ]


    # ── Read-only / benign sink patterns ─────────────────────────────────────────
    # Sinks where input flows but write/exec không xảy ra

    READONLY_SINKS: List[str] = [
        "logger.info", "logger.debug", "logger.warning",
        "logging.info", "logging.debug",
        "console.log", "console.debug",
        "print",        # Python stdout — low risk unless logs expose PII
        "syslog",
        "Log.d", "Log.i",
    ]


    # ── Helpers ───────────────────────────────────────────────────────────────────

    def get_sources_for_stack(stack: str) -> List[str]:
        """Return taint sources for a given stack (lowercased)."""
        stack_key = _normalize_stack(stack)
        return TAINT_SOURCES.get(stack_key, TAINT_SOURCES["python"])


    def get_semgrep_sources(stack: str) -> List[dict]:
        """Return sources as list of dicts for Semgrep rule generation."""
        return [{"pattern": s} for s in get_sources_for_stack(stack)]


    def is_trusted_source(code_snippet: str) -> bool:
        """Check if a code snippet matches a trusted (server-controlled) source."""
        snippet_lower = code_snippet.lower()
        return any(ts.lower() in snippet_lower for ts in TRUSTED_SOURCES)


    def is_test_file(file_path: str) -> bool:
        """Check if a file path looks like a test/fixture/migration file."""
        path_lower = file_path.lower().replace("\\", "/")
        return any(p.lower().replace("\\", "/") in path_lower for p in TEST_FILE_PATTERNS)


    def _normalize_stack(stack: str) -> str:
        mapping = {
            "laravel": "php", "symfony": "php", "codeigniter": "php",
            "flask": "python", "django": "python", "fastapi": "python",
            "express": "node", "nestjs": "node", "nextjs": "node",
            "spring": "java", "springboot": "java",
            "gin": "go", "fiber": "go", "echo": "go",
            "rails": "ruby", "sinatra": "ruby",
            # C# / .NET variants
            "dotnet": "csharp", ".net": "csharp",
            "aspnet": "csharp", "asp.net": "csharp",
            "aspnetcore": "csharp", "mvc": "csharp",
            "blazor": "csharp", "webapi": "csharp",
        }
        return mapping.get(stack.lower(), stack.lower())
