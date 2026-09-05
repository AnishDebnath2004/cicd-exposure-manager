import re

with open('app/static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Check sections
sections = re.findall(r'id=["\'](section-[^"\']+)["\']', content)
print("Found Top Sections:", sections)
assert 'section-user' in sections, "Missing section-user"
assert 'section-admin' in sections, "Missing section-admin"

# 2. Check user subpanels
subpanels = re.findall(r'id=["\'](userSubPanel-[^"\']+)["\']', content)
print("Found User Subpanels:", subpanels)
expected_subpanels = ['userSubPanel-domain1', 'userSubPanel-domain2', 'userSubPanel-domain3', 'userSubPanel-portal']
for p in expected_subpanels:
    assert p in subpanels, f"Missing subpanel: {p}"

# 3. Check user subtabs
subtabs = re.findall(r'id=["\'](userSubTab-[^"\']+)["\']', content)
print("Found User Subtabs:", subtabs)
expected_subtabs = ['userSubTab-domain1', 'userSubTab-domain2', 'userSubTab-domain3', 'userSubTab-portal']
for t in expected_subtabs:
    assert t in subtabs, f"Missing subtab: {t}"

# 4. Check nav tabs
nav_tabs = re.findall(r'id=["\'](navTab-[^"\']+)["\']', content)
print("Found Top Nav Tabs:", nav_tabs)
assert 'navTab-user' in nav_tabs, "Missing navTab-user"
assert 'navTab-admin' in nav_tabs, "Missing navTab-admin"

# 5. Check functions
key_functions = [
    'switchNavTab',
    'switchUserSubTab',
    'updateDomainLockUI',
    'attachResultsToDomain',
    'executeDomainScan',
    'switchAdminSubTab',
    'renderAdminUsersTable',
    'changeUserRole',
    'handleAdminCreateUser',
    'handleSignupSubmit',
    'setAuthState',
    'renderResults',
    'switchUserAuthMode',
    'handleUserLoginSubmit',
    'handleUserSignupSubmit',
    'setUserTargetType',
    'updateUserPortalUI',
    'executeUserScan',
    'renderUserResults',
    'exportUserScan'
]

print("\n--- Key interactive functions check ---")
for fn in key_functions:
    assert f"function {fn}" in content or f"async function {fn}" in content, f"Missing function: {fn}"
    print(f"  [OK] {fn}")

# 6. Check DOM IDs of scans and controls
crucial_ids = [
    'localRepoPath', 'gitRepoUrl', 'gitBranch', 'fileInput', 'dropZone',
    'webTargetUrl', 'dbTargetUri',
    'userTargetInput', 'userLoginForm', 'userSignupForm', 'userResultsArea',
    'domainResults-repository', 'domainResults-website', 'domainResults-database',
    'adminGateBox', 'adminMainContent', 'resultsSection'
]

print("\n--- Crucial DOM Elements check ---")
for cid in crucial_ids:
    assert f'id="{cid}"' in content, f"Missing DOM ID: {cid}"
    print(f"  [OK] {cid}")

print("\nAll UI structural assertions for Merged User Section passed with 100% success!")
