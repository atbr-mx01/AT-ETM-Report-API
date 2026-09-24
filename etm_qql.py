"""
QQL token check for Qualys ETM findings reports.

The token list is copied from "Search Tokens for Findings" (ETM docs):
https://docs.qualys.com/en/etm/latest/search_tips/search_tokens_findings.htm

Tag filtering:
  * Asset tags   -> asset.tag.name:`Tag`     (Asset QQL). Not on the doc page, but accepted by
                                              Qualys (confirmed in Postman). asset.tags.name is
                                              rejected with "Invalid QQL token".
  * Finding tags -> finding.tags.name:`Tag`  (Findings QQL, from the doc page).

Errors (unknown token, unbalanced brackets...) block the run. Warnings (text without a token,
values with spaces not in backticks) are shown but do not block it.

If Qualys adds tokens later, add them to the lists below (or skip the check with --no-qql-check
in the terminal, or the "Skip token check" box on the web page).
"""

import difflib
import re

DOC_URL = "https://docs.qualys.com/en/etm/latest/search_tips/search_tokens_findings.htm"
TAG_TOKEN = "finding.tags.name"        # finding tags, Findings QQL
ASSET_TAG_TOKEN = "asset.tag.name"      # asset tags, Asset QQL (confirmed working with Qualys)
EXTRA_TOKENS = {ASSET_TAG_TOKEN}        # valid tokens that are not on the doc page

_FINDING = """
accessVector applicationURL connectionId connectionName connectionUuid control.id criticality
customNumber1 customNumber2 customNumber3 customNumber4 customNumber5 cveId cvePublishedDate
cvss2BaseScore cvss2Criticality cvss2TemporalScore cvss3BaseScore cvss3TemporalScore cvss4BaseScore
cvss4Criticality cvss4TemporalScore description detectionAge detectionMethod discoveryType epssScore
externalFindingId firstFoundDate ingestedDate id instance isDisabled isExploitAvailable isFound
isIgnored isMitigated isPatchAvailable isQualysPatchable isRebootRequired lastFixedDate lastFoundDate
mitigated.method mitre.attack.subTechnique.id mitre.attack.subTechnique.name mitre.attack.tactic.id
mitre.attack.tactic.name mitre.attack.technique.id mitre.attack.technique.name nonRunningKernel
owaspTopTenName patchReleasedDate policyId policyName port product.vendorId product.version protocol
qds qid qvss reopenedDate requiredPrivilege riskAcceptance.createdDate riskAcceptance.endDate
riskAcceptance.reasonType riskAcceptance.ruleId riskAcceptance.startDate riskAcceptance.type
riskFactor.exploitCodeMaturity riskFactor.exploitType riskFactor.isExploited
riskFactor.isCisaKnownExploit riskFactor.malwareName riskFactor.rti riskFactor.threatActorName
riskFactor.trending ruleName severity sourceId sourceSeverity sourceScoreRange status subType
tags.name technologyCategory technologyName technologyVendor threatIntel.hasNoPatch
threatIntel.isActiveAttack threatIntel.isCisaKnownExploitedVuln threatIntel.isDenialOfService
threatIntel.isEasyExploit threatIntel.isExploitKit threatIntel.isHighDataLoss
threatIntel.isHighLateralMovement threatIntel.isMalware threatIntel.isPredictedHighRisk
threatIntel.isPrivilegeEscalation threatIntel.isPublicExploit threatIntel.isRansomware
threatIntel.isRemoteCodeExecution threatIntel.isUnauthenticatedExploitation threatIntel.isWormable
threatIntel.isZeroDay threatIntel.malwareName title ttd truConfirm.isApplicable truConfirm.status
truConfirm.statusDate ttr type typeDetected vendorFindingId vendorName vendorProductName vendorUrl
wascInfoName
"""

_OTHER = """
asset.criticalityScore asset.compensatoryFactor.name asset.riskFactor.name asset.inventory.createdDate
asset.inventory.source asset.name asset.businessInfo.company asset.businessInfo.department
asset.businessInfo.environment asset.businessInfo.managedBy.username
asset.businessInfo.operationalStatus asset.businessInfo.ownedBy.username
cloud.provider connector.firstFoundDate connector.id connector.lastFoundDate connector.name
container.hasSensor container.noOfContainers container.noOfImages container.product container.version
customAttributes.connectorId customAttributes.key customAttributes.value
missingSoftware.category1 missingSoftware.category2 missingSoftware.detectionScore missingSoftware.name
missingSoftware.product missingSoftware.publisher
operatingSystem.category operatingSystem.category1 operatingSystem.category2 operatingSystem.edition
operatingSystem.installDate operatingSystem.lifecycle.detectionScore operatingSystem.lifecycle.eol
operatingSystem.lifecycle.eos operatingSystem.lifecycle.ga operatingSystem.lifecycle.stage
operatingSystem.marketVersion operatingSystem.name operatingSystem.publisher operatingSystem.update
operatingSystem.version
processor.coresPerSocket processor.multiThreadingStatus processor.name processor.noOfCpu
processor.noOfSockets processor.speed processor.threadsPerCore
qualys.agent.lastCheckedInDate qualys.agent.activationKey.id qualys.agent.activationKey.status
qualys.agent.configurationProfile qualys.agent.connectedFrom qualys.agent.errorStatus qualys.agent.id
qualys.agent.isPassiveSensor qualys.agent.lastActivityDate qualys.agent.lastInventoryDate
qualys.agent.platform qualys.agent.correlationId qualys.agent.status qualys.agent.swCAIdealCandidate
qualys.agent.version
whoIs.registrantEmailId whoIs.registrantOrg whoIs.registrar
apiCollection.name apiCollection.sourceType apiCollection.version apiEndpoint.path apiEndpoint.protocol
apiEndpoint.url application.environment application.supportedLanguages application.baseUrl
application.securityConfig.isHttpsEnabled application.securityConfig.isAuthenticationEnabled
application.securityConfig.allowedOrigins application.securityConfig.isCsrfProtectionEnabled
application.securityConfig.isRateLimitingEnabled application.oauthConfig.isEnabled
application.oauthConfig.provider application.oauthConfig.clientId application.databaseConfig.dbType
application.databaseConfig.host application.databaseConfig.port
application.databaseConfig.databaseName application.databaseConfig.username application.name
application.version application.artifactType
"""

# Group tokens: parent:(child:value and child:value)
GROUPS = {
    "asset.interface": "address dnsAddress gatewayAddress hostname macAddress manufacturer name netmask",
    "qualys.scan": "firstScanDate lastScanDate type",
    "software": ("architecture category category1 category2 component discoverySources edition "
                 "firstFoundDate installDate lastUpdatedDate name hasRunningInstance isPackageComponent "
                 "lifecycle.eol isPackage isPCSupported isRequired license.category "
                 "lifecycle.detectionScore lifecycle.eos lifecycle.ga lifecycle.stage marketVersion "
                 "product publisher supportStage version type"),
    "whoIs": "createdDate expirationDate registrantCountry",
    "application.featureFlag": "featureName isEnabled",
}

TOKENS = {f"finding.{t}" for t in _FINDING.split()} | set(_OTHER.split()) | EXTRA_TOKENS
GROUP_CHILDREN = {g: set(c.split()) for g, c in GROUPS.items()}
ALL_NAMES = sorted(TOKENS | {f"{g}:({c}" for g, cs in GROUP_CHILDREN.items() for c in cs})
_LOWER = {t.lower(): t for t in TOKENS}
_GROUP_LOWER = {g.lower(): g for g in GROUP_CHILDREN}

_TOKEN_RE = re.compile(r"[A-Za-z_][\w.]*")


QUOTED = "\x01"  # placeholder for a quoted / backticked value


def _strip_values(qql):
    """Replace quoted / backticked values with a placeholder so their content (spaces, colons,
    and/or) is not read as QQL syntax."""
    out, i, problems = [], 0, []
    while i < len(qql):
        ch = qql[i]
        if ch in "`\"'":
            j = qql.find(ch, i + 1)
            if j == -1:
                problems.append(f"Missing closing {ch} (opened at position {i + 1}).")
                out.append(QUOTED * (len(qql) - i))
                break
            out.append(QUOTED * (j - i + 1))
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), problems


def _suggest(name, candidates):
    m = difflib.get_close_matches(name, candidates, n=3, cutoff=0.6)
    return f" Did you mean: {', '.join(m)}?" if m else ""


def _check_token(name, text, colon, stack, kind, problems):
    k = colon + 1
    while k < len(text) and text[k] == " ":
        k += 1
    opens_group = k < len(text) and text[k] == "("
    group = next((g for g in reversed(stack) if g), None)
    if group:  # child field inside a group, e.g. software:(name:...)
        children = GROUP_CHILDREN.get(_GROUP_LOWER.get(group.lower(), group), set())
        if name.lower() not in {c.lower() for c in children}:
            problems.append(f"Unknown field '{name}' inside {group}:( ... )."
                            + _suggest(name, sorted(children)))
    elif name.lower() in _GROUP_LOWER:
        if not opens_group:
            g = _GROUP_LOWER[name.lower()]
            problems.append(f"'{name}' must be used as {name}:(field:value), "
                            f"e.g. {name}:({sorted(GROUP_CHILDREN[g])[0]}:...).")
    elif name.lower() not in _LOWER:
        hint = ""
        if "tag" in name.lower():
            hint = (f" For asset tags use {ASSET_TAG_TOKEN}:`TagName` (Asset QQL); for finding tags "
                    f"use {TAG_TOKEN}:`TagName` (Findings QQL).")
        problems.append(f"Unknown token '{name}'." + (hint or _suggest(name, ALL_NAMES)))
    elif kind == "asset" and name.lower().startswith("finding."):
        problems.append(f"'{_LOWER[name.lower()]}' is a finding token: put it in the Findings QQL, "
                        f"not the Asset QQL.")


def check_qql(qql, kind="findings"):
    """Return (errors, warnings). kind is 'findings' or 'asset'."""
    qql = (qql or "").strip()
    if not qql:
        return [], []
    warnings = []
    text, problems = _strip_values(qql)

    for open_, close_ in ("()", "[]"):
        if text.count(open_) != text.count(close_):
            problems.append(f"Unbalanced {open_}{close_} brackets.")

    example = (f"{ASSET_TAG_TOKEN}:`{{0}}`" if kind == "asset" else f"{TAG_TOKEN}:`{{0}}`")
    last = {"pair": None}   # (token, unquoted value) read just before the current words
    stack = []          # open parentheses: group name (e.g. "software") or None for plain grouping
    expecting = None    # token waiting for its value
    loose = []          # consecutive words that are not part of any token:value

    def flush_loose():
        if loose:
            phrase = " ".join(loose)
            pair = last["pair"]
            if pair:  # e.g. asset.tag.name:Firewall Detected
                token, value = pair
                warnings.append(
                    f"'{token}:{value} {phrase}': a value with spaces should be in backticks, "
                    f"otherwise Qualys may only use '{value}'. Suggested: {token}:`{value} {phrase}`")
            else:
                bare = phrase.strip("`\"' ")
                warnings.append(f"'{phrase}' has no token in front of it. Did you mean "
                                f"{example.format(bare)}?")
            loose.clear()
        last["pair"] = None

    qql_token = None
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if expecting is not None:  # read the value of the previous token
            if ch == "(":           # group token, e.g. software:(name:x)
                stack.append(expecting if expecting.lower() in _GROUP_LOWER else None)
                i += 1
            elif ch == "[":
                j = text.find("]", i)
                i = n if j == -1 else j + 1
            elif ch == QUOTED:
                while i < n and text[i] == QUOTED:
                    i += 1
            elif ch == ")":
                problems.append(f"Token '{expecting}' has no value.")
            else:
                start = i
                while i < n and not text[i].isspace() and text[i] not in "()":
                    i += 1
                expecting, value = None, qql[start:i]
                last["pair"] = (qql_token, value)
                continue
            expecting = None
            last["pair"] = None
            continue
        if ch == "(":
            flush_loose()
            stack.append(None)
            i += 1
            continue
        if ch == ")":
            flush_loose()
            if stack:
                stack.pop()
            i += 1
            continue
        if ch in "[" + QUOTED:
            j = text.find("]", i) + 1 if ch == "[" else i
            if ch == QUOTED:
                while j < n and text[j] == QUOTED:
                    j += 1
            loose.append(qql[i:j or n].strip())
            i = j or n
            continue
        m = re.match(r"[^\s()\[\]:" + QUOTED + r"]+", text[i:])
        if not m:
            i += 1
            continue
        word = m.group(0)
        j = i + len(word)
        k = j
        while k < n and text[k] == " ":
            k += 1
        if k < n and text[k] == ":":            # it's a token
            flush_loose()
            _check_token(word, text, k, stack, kind, problems)
            expecting = qql_token = word
            i = k + 1
            continue
        if word.lower() in ("and", "or", "not"):
            flush_loose()
        else:
            loose.append(word)
        i = j
    flush_loose()
    if expecting is not None:
        problems.append(f"Token '{expecting}' has no value.")
    # drop duplicates, keep order
    return list(dict.fromkeys(problems)), list(dict.fromkeys(warnings))


def check_all(findings_qql, asset_qql):
    """Return {'findings': [errors], 'asset': [errors], 'warnings': {'findings': [...], 'asset': [...]}}.
    Only errors should block a run."""
    fe, fw = check_qql(findings_qql, "findings")
    ae, aw = check_qql(asset_qql, "asset")
    return {"findings": fe, "asset": ae, "warnings": {"findings": fw, "asset": aw}}
