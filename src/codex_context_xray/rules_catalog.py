"""Human explanations for every deterministic X-Ray finding identifier."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RuleExplanation:
    rule_id: str
    title: str
    explanation: str
    remediation: str


def _rule(
    rule_id: str,
    title: str,
    explanation: str,
    remediation: str,
) -> RuleExplanation:
    return RuleExplanation(rule_id, title, explanation, remediation)


_ROWS = (
    _rule(
        "CONFIG_INVALID_CLI_OVERRIDE",
        "Invalid command-line override",
        "A -c value is not valid KEY=VALUE TOML and cannot join the config chain.",
        "Quote the TOML value correctly and keep every dotted key component non-empty.",
    ),
    _rule(
        "CONFIG_INVALID_TOML",
        "Invalid TOML configuration",
        "The configuration file cannot participate in deterministic resolution.",
        "Fix the TOML parse error and scan again.",
    ),
    _rule(
        "CONFIG_PATH_ESCAPE",
        "Configuration path escapes the scan root",
        "A .codex layer resolves outside the repository or opted-in user root.",
        "Keep the configuration inside its declared scope.",
    ),
    _rule(
        "CONFIG_PROFILE_MISSING",
        "Selected profile is missing",
        "The opted-in user configuration does not contain the selected profile file.",
        "Create the profile file or select an existing profile.",
    ),
    _rule(
        "CONFIG_PROFILE_REQUIRES_USER_SCOPE",
        "Profile needs user scope",
        "Profiles live in user configuration, which the repository-only scan excludes.",
        "Add --include-user deliberately, or omit --profile.",
    ),
    _rule(
        "CONFIG_PROJECT_KEY_IGNORED",
        "Project attempted a user-only setting",
        "Codex rejects this identity, provider, telemetry, or profile key from a project.",
        "Move the setting to user config, or remove it from the project.",
    ),
    _rule(
        "HOOKS_INVALID",
        "Hook declaration is invalid",
        "The hook file or inline hook table cannot be interpreted structurally.",
        "Fix the JSON/TOML shape without executing the hook, then scan again.",
    ),
    _rule(
        "HOOKS_MIXED_REPRESENTATIONS",
        "Hook representations are merged",
        "hooks.json and inline hooks coexist in one layer; Codex merges and warns.",
        "Keep one hook representation per configuration layer.",
    ),
    _rule(
        "INSTRUCTIONS_INVALID_BUDGET",
        "Instruction byte budget is invalid",
        "project_doc_max_bytes must be a positive integer.",
        "Set a positive byte limit or remove the override to use the default.",
    ),
    _rule(
        "INSTRUCTIONS_PATH_ESCAPE",
        "Instruction path escapes the scan root",
        "An instruction link resolves outside the repository or opted-in user root.",
        "Keep the instruction file inside its declared scope.",
    ),
    _rule(
        "INSTRUCTIONS_READ_ERROR",
        "Instruction file could not be read",
        "A selected instruction file was not safely readable as UTF-8 text.",
        "Fix permissions or encoding, and keep the file inside the scan root.",
    ),
    _rule(
        "INSTRUCTIONS_TRUNCATED",
        "Instruction chain reached its byte budget",
        "Codex stops adding project instruction bytes at project_doc_max_bytes.",
        "Shorten the chain or deliberately raise project_doc_max_bytes.",
    ),
    _rule(
        "MCP_INVALID_CONFIGURATION",
        "MCP declaration is invalid",
        "The server table has an unsupported or internally inconsistent structure.",
        "Correct the server transport and option types.",
    ),
    _rule(
        "MCP_INVALID_TOOL_FILTER",
        "MCP tool filter is invalid",
        "enabled_tools or disabled_tools is not a list of tool names.",
        "Use a TOML array of strings.",
    ),
    _rule(
        "MCP_REQUIRED_DISABLED",
        "Required MCP server is disabled",
        "A declaration marks the same server both required and disabled.",
        "Enable the server or remove required=true.",
    ),
    _rule(
        "MCP_SERVER_OVERRIDE",
        "MCP server declaration is overridden",
        "A higher-precedence layer redeclares the same server id.",
        "Keep the override if intentional, or give independent servers unique ids.",
    ),
    _rule(
        "MCP_TOOL_FILTER_OVERLAP",
        "MCP tool is both enabled and disabled",
        "The same tool appears in overlapping allow and deny declarations.",
        "Remove the overlap and keep one explicit policy.",
    ),
    _rule(
        "PATH_ESCAPE",
        "Rule path escapes the scan root",
        "A rule path resolves outside the repository or opted-in user root.",
        "Move it inside the root or inspect it separately.",
    ),
    _rule(
        "PERMISSIONS_DEFAULT_MISSING",
        "Permission profiles have no selected default",
        "Profiles are declared, but default_permissions does not select one.",
        "Set default_permissions to a built-in or declared profile.",
    ),
    _rule(
        "PERMISSIONS_FORBIDDEN_PARENT",
        "Permission profile extends a forbidden parent",
        "Custom profiles may not extend the unrestricted danger-full-access profile.",
        "Extend :read-only, :workspace, or another safe acyclic profile.",
    ),
    _rule(
        "PERMISSIONS_INHERITANCE_CYCLE",
        "Permission profile inheritance cycle",
        "A cyclic extends graph has no deterministic base policy.",
        "Break the cycle and extend a built-in or acyclic named profile.",
    ),
    _rule(
        "PERMISSIONS_INVALID_DEFAULT",
        "Invalid default permission profile",
        "default_permissions is not a profile name string.",
        "Use a declared profile name or supported built-in profile.",
    ),
    _rule(
        "PERMISSIONS_INVALID_PROFILE",
        "Invalid permission profile",
        "A profile table or its extends declaration has the wrong type.",
        "Correct the profile structure and scan again.",
    ),
    _rule(
        "PERMISSIONS_LEGACY_CONFLICT",
        "Legacy sandbox disables permission profiles",
        "Permission profiles do not compose with legacy sandbox settings.",
        "Choose permission profiles or legacy sandbox settings, not both.",
    ),
    _rule(
        "PERMISSIONS_UNKNOWN_DEFAULT",
        "Selected permission profile is unknown",
        "default_permissions names neither a built-in nor a declared profile.",
        "Correct the name or add the missing profile.",
    ),
    _rule(
        "PERMISSIONS_UNKNOWN_PARENT",
        "Permission profile parent is unknown",
        "A custom profile extends a profile that is not declared or built in.",
        "Correct the parent name or define it in an active layer.",
    ),
    _rule(
        "RULES_INVALID",
        "Exec policy rule is invalid",
        "The parsed prefix_rule is missing a supported pattern or decision.",
        "Use a literal prefix and allow, prompt, or forbidden decision.",
    ),
    _rule(
        "RULES_OVERLAP",
        "Exec policy rules overlap",
        "Multiple prefixes can match one command; Codex applies the strictest decision.",
        "Keep the overlap only when the restrictive result is intentional.",
    ),
    _rule(
        "RULES_PARSE_ERROR",
        "Exec policy file cannot be parsed",
        "Malformed Starlark prevents reliable static interpretation.",
        "Validate with codex execpolicy check and correct the syntax.",
    ),
    _rule(
        "RULES_STATIC_ANALYSIS_INCOMPLETE",
        "Rule needs runtime evaluation",
        "The Starlark is valid but computes values the safe static subset does not execute.",
        "Use literal prefix_rule arguments for a fully observed result.",
    ),
    _rule(
        "SKILL_DIRECTORY_READ_ERROR",
        "Skill directory could not be read",
        "Discovery could not safely enumerate a declared Skill location.",
        "Fix permissions and keep the directory inside the selected scope.",
    ),
    _rule(
        "SKILL_DUPLICATE_NAME",
        "Duplicate Skill name",
        "Codex does not merge same-name Skills; both can remain discoverable.",
        "Give each Skill a stable, unique frontmatter name.",
    ),
    _rule(
        "SKILL_INVALID_FRONTMATTER",
        "Skill frontmatter is invalid",
        "SKILL.md lacks valid YAML with required name and description fields.",
        "Correct the YAML frontmatter and required fields.",
    ),
    _rule(
        "SKILL_INVALID_OPENAI_METADATA",
        "Skill OpenAI metadata is invalid",
        "Optional agents/openai.yaml cannot be parsed safely.",
        "Correct the YAML structure or remove the optional file.",
    ),
    _rule(
        "SKILL_PATH_ESCAPE",
        "Skill path escapes the scan root",
        "A Skill symlink or junction resolves outside the allowed scope.",
        "Keep the Skill inside the repository or explicitly opted-in user root.",
    ),
    _rule(
        "TARGET_OUTSIDE_REPOSITORY",
        "Target is outside the detected repository",
        "A root-to-target chain cannot be formed inside the selected repository root.",
        "Scan the target directly or choose the correct repository root.",
    ),
    _rule(
        "instructions.same-directory-override",
        "Same-directory instruction override",
        "AGENTS.override.md wins over AGENTS.md in the same directory.",
        "Remove the override when the default instructions should become active.",
    ),
)

RULES: dict[str, RuleExplanation] = {item.rule_id: item for item in _ROWS}

_ALIASES = {
    "config.invalid": "CONFIG_INVALID_TOML",
    "config.project-key-ignored": "CONFIG_PROJECT_KEY_IGNORED",
    "hooks.mixed-declarations": "HOOKS_MIXED_REPRESENTATIONS",
    "hooks.mixed-representation": "HOOKS_MIXED_REPRESENTATIONS",
    "instructions.truncated": "INSTRUCTIONS_TRUNCATED",
    "mcp.same-id-override": "MCP_SERVER_OVERRIDE",
    "mcp.tool-conflict": "MCP_TOOL_FILTER_OVERLAP",
    "permissions.inheritance-cycle": "PERMISSIONS_INHERITANCE_CYCLE",
    "permissions.legacy-conflict": "PERMISSIONS_LEGACY_CONFLICT",
    "permissions.legacy-wins": "PERMISSIONS_LEGACY_CONFLICT",
    "privacy.path-escape": "PATH_ESCAPE",
    "rules.overlap": "RULES_OVERLAP",
    "rules.parse-error": "RULES_PARSE_ERROR",
    "skills.duplicate-name": "SKILL_DUPLICATE_NAME",
}


def explain(rule_id: str) -> RuleExplanation | None:
    canonical = _ALIASES.get(rule_id, rule_id)
    return RULES.get(canonical)
