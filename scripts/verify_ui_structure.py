import re

with open('app/static/index.html', 'r', encoding='utf-8') as f:
    content = f.read()

nav_tabs = re.findall(r'id=["\'](navTab-[^"\']+)["\']', content)
sections = re.findall(r'id=["\'](section-[^"\']+)["\']', content)

print("Found Nav Tabs:", nav_tabs)
print("Found Sections:", sections)

# Check required sections
expected_sections = ['section-domain1', 'section-domain2', 'section-domain3', 'section-admin', 'section-user']
for s in expected_sections:
    assert s in sections, f"Missing section: {s}"

expected_tabs = ['navTab-domain1', 'navTab-domain2', 'navTab-domain3', 'navTab-admin', 'navTab-user']
for t in expected_tabs:
    assert t in nav_tabs, f"Missing navTab: {t}"

print("\n--- Testing key interactive handlers ---")
key_functions = [
    'switchNavTab',
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

for fn in key_functions:
    assert f"function {fn}" in content or f"async function {fn}" in content, f"Missing function: {fn}"
    print(f"  [OK] {fn}")

print("\nAll UI structural assertions passed successfully!")
