import pytest
import mmguero
import requests
import logging

LOGGER = logging.getLogger(__name__)

UPLOAD_ARTIFACTS = [
    "pcap/other/Digital Bond S4/Advantech.pcap",
    "pcap/other/Digital Bond S4/BACnet_FIU.pcap",
    "pcap/other/Digital Bond S4/BACnet_Host.pcap",
    "pcap/other/Digital Bond S4/MicroLogix56.pcap",
    "pcap/other/Digital Bond S4/Modicon.pcap",
    "pcap/other/Digital Bond S4/WinXP.pcap",
    "pcap/other/Digital Bond S4/iFix_Client86.pcap",
    "pcap/other/Digital Bond S4/iFix_Server119.pcap",
    "pcap/plugins/zeek-EternalSafety/eternalchampion.pcap",
]

NETBOX_ENRICH = True


EXPECTED_GROUPS = {
    "admin",
    "netbox_read_access",
    "netbox_read_write_access",
}

EXPECTED_PERMISSIONS = {
    "admin_permission",
    "netbox_read_access_permission",
    "netbox_read_access_token_manage_permission",
    "netbox_read_access_user_config_permission",
    "netbox_read_write_access_permission",
    "netbox_read_write_access_token_manage_permission",
    "netbox_read_write_access_user_config_permission",
}

# Object types that must NOT appear in read-only or read-write base permissions
OWNER_TYPES = {"users.owner", "users.ownergroup"}

# Object types that must NOT appear in read-only or read-write base permissions
RESTRICTED_TYPES = {
    "account.usertoken",
    "auth.group",
    "auth.permission",
    "contenttypes.contenttype",
    "core.autosyncrecord",
    "core.configrevision",
    "core.datafile",
    "core.datasource",
    "core.job",
    "core.managedfile",
    "core.objectchange",
    "core.objecttype",
    "users.group",
    "users.objectpermission",
    "users.user",
    "users.owner",
    "users.ownergroup",
}

EXPECTED_PLUGINS = {
    'netbox_healthcheck_plugin',
    'netbox_initializers',
    'netbox_topology_views',
}

EXPECTED_SCRIPTS = {
    'NewBranchScript',
}

# The commented-out ones here actually *are* normally enriched, but
# they happen to overlap with the IP range specified to test `NETBOX_AUTO_POPULATE_SUBNETS`
# in so I'm just excluding them here.
LOGSTASH_NETBOX_ENRICHMENT_DATASETS = [
    # "filescan.strelka",
    "suricata.alert",
    "zeek.conn",
    # "zeek.dce_rpc",
    "zeek.dhcp",
    "zeek.dns",
    "zeek.known_hosts",
    "zeek.known_services",
    # "zeek.login",
    "zeek.ntlm",
    "zeek.notice",
    # "zeek.rdp",
    # "zeek.rfb",
    # "zeek.signatures",
    "zeek.smb_cmd",
    "zeek.smb_files",
    "zeek.smb_mapping",
    "zeek.software",
    # "zeek.ssh",
    "zeek.weird",
]


def _netbox_mapi_get(malcolm_url, malcolm_http_auth, path):
    response = requests.get(
        f"{malcolm_url}/mapi/netbox{path}",
        headers={"Content-Type": "application/json"},
        json={"format": "json"},
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    return response.json()


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_cross_segment(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_netbox_cross_segment

    After netbox enrichment/autopopulation happens, check that cross-segment traffic was detected

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.provider,source.segment.name,destination.segment.name",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "!source.segment.name": None,
                "!destination.segment.name": None,
                "tags": "cross_segment",
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    responseJson = response.json()
    results = {}
    for providerBucket in mmguero.deep_get(responseJson, ["event.provider", "buckets"], []):
        providerName = providerBucket["key"]
        results[providerName] = []
        for sourceSegmentBucket in mmguero.deep_get(providerBucket, ["source.segment.name", "buckets"], [{}]):
            sourceSegmentName = sourceSegmentBucket["key"]
            for destinationSegmentBucket in mmguero.deep_get(
                sourceSegmentBucket, ["destination.segment.name", "buckets"], [{}]
            ):
                destinationSegmentName = destinationSegmentBucket["key"]
                crossSegmentCount = destinationSegmentBucket["doc_count"]
                results[providerName].append(f"{sourceSegmentName} -> {destinationSegmentName} = {crossSegmentCount}")
    LOGGER.debug(results)
    assert results.get("zeek", None)
    assert results.get("suricata", None)


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_datasets(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_netbox_datasets

    Check which event provider/dataset have netbox enrichment

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    response = requests.post(
        f"{malcolm_url}/mapi/agg/event.provider,event.dataset",
        headers={"Content-Type": "application/json"},
        json={
            "from": "0",
            "filter": {
                "tags": "netbox",
            },
        },
        allow_redirects=True,
        auth=malcolm_http_auth,
        verify=False,
    )
    response.raise_for_status()
    responseJson = response.json()
    found_datasets = {
        f"{provider['key']}.{dataset['key']}"
        for provider in responseJson["event.provider"]["buckets"]
        for dataset in provider["event.dataset"]["buckets"]
    }
    LOGGER.debug(found_datasets)
    assert set(LOGSTASH_NETBOX_ENRICHMENT_DATASETS).issubset(
        found_datasets
    ), f"Missing datasets: {set(LOGSTASH_NETBOX_ENRICHMENT_DATASETS) - found_datasets}"


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_enrichment(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    """test_netbox_enrichment

    Check for various fields populated by netbox enrichment (manufacturer, device type, device name, etc.)

    Args:
        malcolm_http_auth (HTTPBasicAuth): username and password for the Malcolm instance
        malcolm_url (str): URL for connecting to the Malcolm instance
        artifact_hash_map (defaultdict(lambda: None)): a map of artifact files' full path to their file hash
    """
    for field in [
        "destination.device.uninventoried",
        "related.device_name",
        "related.manufacturer",
        "related.uninventoried",
        "source.device.uninventoried",
        "zeek.software.name",
        "zeek.software.software_type",
    ]:
        response = requests.post(
            f"{malcolm_url}/mapi/agg/{field}",
            headers={"Content-Type": "application/json"},
            json={
                "from": "0",
                "filter": {
                    f"!{field}": None,
                    "tags": [artifact_hash_map[x] for x in mmguero.get_iterable(UPLOAD_ARTIFACTS)],
                },
            },
            allow_redirects=True,
            auth=malcolm_http_auth,
            verify=False,
        )
        response.raise_for_status()
        buckets = {item['key']: item['doc_count'] for item in mmguero.deep_get(response.json(), [field, 'buckets'], [])}
        LOGGER.debug(buckets)
        assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_api_endpoints(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    for uri in [
        "mapi/netbox",
        "mapi/netbox/api",
        "netbox/api",
    ]:
        for trailing in [
            "",
            "/",
            "/dcim/sites",
            "/dcim/sites/",
        ]:
            response = requests.get(
                f"{malcolm_url}/{uri}{trailing}",
                headers={"Content-Type": "application/json"},
                json={
                    "format": "json",
                },
                allow_redirects=True,
                auth=malcolm_http_auth,
                verify=False,
            )
            response.raise_for_status()
            results = response.json()
            LOGGER.debug(f"{uri}{trailing}: {results}")
            assert results.get('dcim', results.get('count', 0))


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_prefixes(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/ipam/prefixes/")
    buckets = [
        {
            "prefix": item["prefix"],
            "description": item["description"],
            "site": item["scope"]["name"] if item.get("scope") else None,
            "tags": [tag["slug"] for tag in item.get("tags", [])],
        }
        for item in data.get("results", [])
    ]
    LOGGER.debug(buckets)
    assert all("malcolm-autopopulated" in p["tags"] for p in buckets)
    assert len({(p["site"], p["prefix"]) for p in buckets}) == len(
        buckets
    ), "Duplicate prefixes found for the same site"
    assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_devices(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/dcim/devices/")
    buckets = [
        {
            "name": d["name"],
            "site": d["site"]["name"] if d.get("site") else None,
            "status": d["status"]["label"] if d.get("status") else None,
            "role": d["role"]["name"] if d.get("role") else None,
            "primary_ip": d["primary_ip"]["address"] if d.get("primary_ip") else None,
            "tags": [tag["slug"] for tag in d.get("tags", [])],
        }
        for d in data.get("results", [])
    ]
    LOGGER.debug(buckets)
    assert all("malcolm-autopopulated" in p["tags"] for p in buckets)
    assert any("hostname-unknown" in p["tags"] for p in buckets)
    assert any("hostname-unknown" not in p["tags"] for p in buckets)
    assert all(p["primary_ip"] for p in buckets)
    assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_manuf(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/dcim/manufacturers/")

    buckets = [
        {
            "name": m["name"],
            "tags": [tag["slug"] for tag in m.get("tags", [])],
        }
        for m in data.get("results", [])
    ]
    LOGGER.debug(buckets)
    assert any("malcolm-autopopulated" in m["tags"] for m in buckets)
    assert buckets


@pytest.mark.netbox
@pytest.mark.mapi
@pytest.mark.pcap
def test_netbox_auto_subnet_filters(
    malcolm_http_auth,
    malcolm_url,
    artifact_hash_map,
):
    # this should *NOT* return anything, because:
    #   NETBOX_AUTO_POPULATE_SUBNETS=*:!10.100.0.0/16
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/ipam/prefixes/?prefix=10.100.0.0/16")
    buckets = [
        {
            "prefix": item["prefix"],
            "description": item["description"],
            "site": item["scope"]["name"] if item.get("scope") else None,
            "tags": [tag["slug"] for tag in item.get("tags", [])],
        }
        for item in data.get("results", [])
    ]
    LOGGER.debug(buckets)
    assert not buckets


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_device_roles_have_hierarchy(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """device roles include nested roles (parent set, _depth > 0)"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/dcim/device-roles/?limit=0")
    roles = data["results"]
    LOGGER.debug(f"total device roles: {data['count']}")

    nested = [r for r in roles if r.get("parent") is not None and r.get("_depth", 0) > 0]
    root = [r for r in roles if r.get("parent") is None and r.get("_depth", 0) == 0]

    LOGGER.debug(f"root roles: {len(root)}, nested roles: {len(nested)}")
    assert len(root) >= 1, "no root-level device roles found"
    assert len(nested) >= 1, "no nested device roles found (hierarchy not created)"

    # spot-check a few known parent/child relationships
    role_map = {r["name"]: r for r in roles}
    for child, parent in [
        ("PLC", "Controller"),
        ("Firewall", "Gateway"),
        ("HMI", "OT Client"),
        ("IDS", "Monitoring"),
    ]:
        if child in role_map and parent in role_map:
            assert (
                role_map[child]["parent"]["name"] == parent
            ), f"expected {child}.parent == {parent}, got {role_map[child].get('parent')}"


# ── SUPERUSER ──────────────────────────────────────────────────────────────────


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_superuser_exists(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """admin user exists and is a superuser"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/users/")
    users = {u["username"]: u for u in data["results"]}
    LOGGER.debug(f"users: {list(users.keys())}")
    assert "admin" in users, "superuser 'admin' not found"
    assert users["admin"]["is_active"], "superuser 'admin' is not active"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_superuser_token_exists(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """admin has exactly one token, V1, enabled, with plaintext set (key must be null for V1)"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/tokens/")
    tokens = data["results"]
    LOGGER.debug(f"tokens: {tokens}")

    admin_tokens = [t for t in tokens if t.get("user", {}).get("username") == "admin"]
    assert len(admin_tokens) >= 1, "no token found for admin user"

    t = admin_tokens[0]
    assert t["version"] == 1, f"expected V1 token, got version={t['version']}"
    assert t["enabled"], "admin token is not enabled"
    assert t["key"] is None, "V1 token should have key=null"
    # plaintext is masked in API output but display should show the masked form
    assert t["display"].startswith("*"), f"unexpected token display format: {t['display']}"


# ── GROUPS ─────────────────────────────────────────────────────────────────────


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_default_groups_exist(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """all three default groups are present"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/groups/")
    found = {g["name"] for g in data["results"]}
    LOGGER.debug(f"groups found: {found}")
    missing = EXPECTED_GROUPS - found
    assert not missing, f"missing groups: {missing}"


# ── PERMISSIONS ────────────────────────────────────────────────────────────────


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_default_permissions_exist(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """all seven default permissions are present"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    found = {p["name"] for p in data["results"]}
    LOGGER.debug(f"permissions found: {found}")
    missing = EXPECTED_PERMISSIONS - found
    assert not missing, f"missing permissions: {missing}"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_admin_permission_has_owner_types(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """admin_permission must include users.owner and users.ownergroup"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}
    admin_perm = perms.get("admin_permission")
    assert admin_perm, "admin_permission not found"
    object_types = set(admin_perm["object_types"])
    LOGGER.debug(f"admin_permission object_types (owner-related): {object_types & OWNER_TYPES}")
    missing = OWNER_TYPES - object_types
    assert not missing, f"admin_permission missing owner types: {missing}"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_read_access_permission_excludes_restricted(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """netbox_read_access_permission must not include restricted/owner types"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}
    perm = perms.get("netbox_read_access_permission")
    assert perm, "netbox_read_access_permission not found"
    object_types = set(perm["object_types"])
    violations = RESTRICTED_TYPES & object_types
    LOGGER.debug(f"netbox_read_access_permission restricted violations: {violations}")
    assert not violations, f"netbox_read_access_permission contains restricted types: {violations}"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_read_write_permission_excludes_restricted(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """netbox_read_write_access_permission must not include restricted/owner types"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}
    perm = perms.get("netbox_read_write_access_permission")
    assert perm, "netbox_read_write_access_permission not found"
    object_types = set(perm["object_types"])
    violations = RESTRICTED_TYPES & object_types
    LOGGER.debug(f"netbox_read_write_access_permission restricted violations: {violations}")
    assert not violations, f"netbox_read_write_access_permission contains restricted types: {violations}"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_token_manage_permissions_scoped(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """token_manage permissions must only cover users.token and have user constraint"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}
    for perm_name in (
        "netbox_read_access_token_manage_permission",
        "netbox_read_write_access_token_manage_permission",
    ):
        perm = perms.get(perm_name)
        assert perm, f"{perm_name} not found"
        assert perm["object_types"] == [
            "users.token"
        ], f"{perm_name} should only cover users.token, got: {perm['object_types']}"
        assert perm.get("constraints", {}).get("user") == "$user", f"{perm_name} missing user=$user constraint"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_user_config_permissions_scoped(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """user_config permissions must only cover users.userconfig and have user constraint"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}
    for perm_name in (
        "netbox_read_access_user_config_permission",
        "netbox_read_write_access_user_config_permission",
    ):
        perm = perms.get(perm_name)
        assert perm, f"{perm_name} not found"
        assert perm["object_types"] == [
            "users.userconfig"
        ], f"{perm_name} should only cover users.userconfig, got: {perm['object_types']}"
        assert perm.get("constraints", {}).get("user") == "$user", f"{perm_name} missing user=$user constraint"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_permissions_group_assignments(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """each permission is assigned to exactly the right group"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/users/permissions/")
    perms = {p["name"]: p for p in data["results"]}

    expected_assignments = {
        "admin_permission": "admin",
        "netbox_read_access_permission": "netbox_read_access",
        "netbox_read_access_token_manage_permission": "netbox_read_access",
        "netbox_read_access_user_config_permission": "netbox_read_access",
        "netbox_read_write_access_permission": "netbox_read_write_access",
        "netbox_read_write_access_token_manage_permission": "netbox_read_write_access",
        "netbox_read_write_access_user_config_permission": "netbox_read_write_access",
    }
    for perm_name, expected_group in expected_assignments.items():
        perm = perms.get(perm_name)
        assert perm, f"{perm_name} not found"
        groups = [g["name"] for g in perm.get("groups", [])]
        assert expected_group in groups, f"{perm_name} not assigned to {expected_group}, got: {groups}"


# ── SCRIPTS ────────────────────────────────────────────────────────────────────


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_scripts_endpoint(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """extras/scripts endpoint lists installed custom scripts"""
    scripts = set(
        [
            item["name"]
            for item in _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/extras/scripts/").get("results", [])
        ]
    )
    LOGGER.debug(f"installed scripts: {scripts}")
    missing = EXPECTED_SCRIPTS - scripts
    assert not missing, f"missing expected scripts: {missing}"


# ── PLUGINS ────────────────────────────────────────────────────────────────────


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_plugins_endpoint(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """plugins endpoint lists expected plugins"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/plugins/installed-plugins/")
    LOGGER.debug(f"installed plugins: {data}")
    installed = {p["package"] for p in data}
    LOGGER.debug(f"installed plugin names: {installed}")
    missing = EXPECTED_PLUGINS - installed
    assert not missing, f"missing expected plugins: {missing}"


@pytest.mark.netbox
@pytest.mark.mapi
def test_netbox_status(malcolm_http_auth, malcolm_url, artifact_hash_map):
    """status endpoint returns sane NetBox version and at least one rq worker"""
    data = _netbox_mapi_get(malcolm_url, malcolm_http_auth, "/status/")
    LOGGER.debug(f"netbox status: {data}")

    assert "netbox-version" in data, "netbox-version missing from status"
    version = data["netbox-version"]
    major, minor, *_ = version.split(".")
    assert int(major) >= 4, f"unexpected major version: {version}"
    assert int(minor) >= 5, f"expected at least 4.5.x, got: {version}"

    assert data.get("rq-workers-running", 0) >= 1, f"no rq workers running: {data.get('rq-workers-running')}"

    plugins = data.get("plugins", {})
    LOGGER.debug(f"plugins in status: {plugins}")
    for expected in EXPECTED_PLUGINS:
        assert expected in plugins, f"plugin {expected} not in status plugins"
