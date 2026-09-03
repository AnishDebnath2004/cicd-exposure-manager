"""
app/core/auto_discovery.py
Automatic Infrastructure Footprint & Asset Discovery Engine.
Parses repositories for docker-compose, .env configs, CI/CD pipelines, and package manifests
to automatically discover live websites, database endpoints, and exposed network services.
"""

import os
import re
import yaml
import json
from typing import List, Dict, Set, Optional, Tuple
from app.models.schemas import AutoDiscoveryResult, DiscoveredService
from app.config import settings


class AutoDiscoveryEngine:
    """Discovers live websites, databases, and exposed services directly from repository code."""

    DB_IMAGE_PATTERNS = {
        "postgres": ("postgres", 5432, "postgresql://postgres:postgres@localhost:5432/app"),
        "postgresql": ("postgres", 5432, "postgresql://postgres:postgres@localhost:5432/app"),
        "mysql": ("mysql", 3306, "mysql://root:root@localhost:3306/app"),
        "mariadb": ("mariadb", 3306, "mysql://root:root@localhost:3306/app"),
        "mongo": ("mongodb", 27017, "mongodb://localhost:27017/app"),
        "mongodb": ("mongodb", 27017, "mongodb://localhost:27017/app"),
        "redis": ("redis", 6379, "redis://localhost:6379/0"),
        "elasticsearch": ("elasticsearch", 9200, "http://localhost:9200"),
        "mssql": ("mssql", 1433, "mssql://sa:Password123!@localhost:1433/app")
    }

    URL_REGEX = re.compile(r"https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s'\"<>]*)?")
    DB_URI_REGEX = re.compile(r"(?:postgres|postgresql|mysql|mariadb|redis|mongodb|mongodb\+srv|elasticsearch|mssql)://[^\s'\"<>]+")

    def discover(self, base_path: str) -> AutoDiscoveryResult:
        """
        Scans base_path for compose files, environment variables, workflows, and package manifests.
        Returns aggregated AutoDiscoveryResult.
        """
        web_targets: Set[str] = set()
        db_targets: Set[str] = set()
        services: List[DiscoveredService] = []
        source_files: Set[str] = set()

        # 1. Parse Docker Compose files
        compose_candidates = [
            "docker-compose.yml", "docker-compose.yaml",
            "compose.yml", "compose.yaml",
            "docker-compose.dev.yml", "docker-compose.local.yml"
        ]
        for cname in compose_candidates:
            cpath = os.path.join(base_path, cname)
            if os.path.isfile(cpath):
                source_files.add(cname)
                comp_services, comp_webs, comp_dbs = self._parse_compose(cpath)
                services.extend(comp_services)
                web_targets.update(comp_webs)
                db_targets.update(comp_dbs)

        # 2. Parse Environment files (.env, .env.example, .env.local, .env.staging)
        for root, dirs, files in os.walk(base_path):
            dirs[:] = [d for d in dirs if d not in settings.scanner.IGNORED_DIRECTORIES]
            for f in files:
                if f.startswith(".env") or f in ("config.env", "app.env"):
                    full_p = os.path.join(root, f)
                    rel_p = os.path.relpath(full_p, base_path)
                    source_files.add(rel_p)
                    env_webs, env_dbs = self._parse_env_file(full_p)
                    web_targets.update(env_webs)
                    db_targets.update(env_dbs)

        # 3. Parse GitHub Actions Workflows for service containers & deployments
        workflow_dir = os.path.join(base_path, ".github", "workflows")
        if os.path.isdir(workflow_dir):
            for f in os.listdir(workflow_dir):
                if f.endswith((".yml", ".yaml")):
                    wpath = os.path.join(workflow_dir, f)
                    rel_p = os.path.relpath(wpath, base_path)
                    w_services, w_webs, w_dbs = self._parse_workflow(wpath)
                    if w_services or w_webs or w_dbs:
                        source_files.add(rel_p)
                        services.extend(w_services)
                        web_targets.update(w_webs)
                        db_targets.update(w_dbs)

        # 4. Parse package.json or web frameworks
        pkg_path = os.path.join(base_path, "package.json")
        if os.path.isfile(pkg_path):
            source_files.add("package.json")
            pkg_webs = self._parse_package_json(pkg_path)
            web_targets.update(pkg_webs)

        # Filter out obvious false positives (e.g., schemas, schema.org)
        clean_webs = [
            w for w in sorted(web_targets)
            if not any(ign in w for ign in ("schema.org", "w3.org", "example.com/ns", "localhost/dummy"))
        ]
        clean_dbs = sorted(db_targets)

        return AutoDiscoveryResult(
            discovered_web_targets=clean_webs,
            discovered_db_targets=clean_dbs,
            discovered_services=services,
            source_files=sorted(source_files)
        )

    def _parse_compose(self, file_path: str) -> Tuple[List[DiscoveredService], Set[str], Set[str]]:
        services: List[DiscoveredService] = []
        webs: Set[str] = set()
        dbs: Set[str] = set()

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict) or "services" not in data:
                return services, webs, dbs

            for sname, sdef in data.get("services", {}).items():
                if not isinstance(sdef, dict):
                    continue

                image = sdef.get("image", "")
                raw_ports = sdef.get("ports", [])
                ports_list: List[str] = []
                for p in raw_ports:
                    if isinstance(p, (str, int)):
                        ports_list.append(str(p))

                # Identify service type
                stype = "service"
                connection_hint = None

                # Check if database
                for img_key, (db_type, default_port, default_conn) in self.DB_IMAGE_PATTERNS.items():
                    if img_key in str(image).lower() or img_key in sname.lower():
                        stype = "database"
                        connection_hint = default_conn
                        dbs.add(default_conn)
                        break

                # Check if web / frontend / api
                if any(k in sname.lower() or k in str(image).lower() for k in ("web", "front", "api", "nginx", "app", "ui")):
                    if stype != "database":
                        stype = "web"
                        for p in ports_list:
                            host_port = p.split(":")[0] if ":" in p else p
                            if host_port.isdigit():
                                webs.add(f"http://localhost:{host_port}")

                # Check environment inside service
                env_defs = sdef.get("environment", {})
                if isinstance(env_defs, dict):
                    for k, val in env_defs.items():
                        v_str = str(val or "")
                        dbs.update(self.DB_URI_REGEX.findall(v_str))
                        webs.update(self.URL_REGEX.findall(v_str))
                elif isinstance(env_defs, list):
                    for item in env_defs:
                        i_str = str(item or "")
                        dbs.update(self.DB_URI_REGEX.findall(i_str))
                        webs.update(self.URL_REGEX.findall(i_str))

                services.append(DiscoveredService(
                    name=sname,
                    service_type=stype,
                    image_or_source=str(image) if image else None,
                    ports=ports_list,
                    connection_hint=connection_hint
                ))

        except Exception:
            pass

        return services, webs, dbs

    def _parse_env_file(self, file_path: str) -> Tuple[Set[str], Set[str]]:
        webs: Set[str] = set()
        dbs: Set[str] = set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            dbs.update(self.DB_URI_REGEX.findall(content))
            webs.update(self.URL_REGEX.findall(content))

            # Look for DB_HOST / DB_PORT combos
            host_m = re.search(r"(?i)(?:DB|DATABASE|POSTGRES|MYSQL)_HOST\s*=\s*['\"]?([a-zA-Z0-9.\-_]+)['\"]?", content)
            port_m = re.search(r"(?i)(?:DB|DATABASE|POSTGRES|MYSQL)_PORT\s*=\s*['\"]?(\d+)['\"]?", content)
            if host_m and port_m:
                h = host_m.group(1)
                p = port_m.group(1)
                if p == "5432":
                    dbs.add(f"postgresql://postgres:postgres@{h}:{p}/app")
                elif p == "3306":
                    dbs.add(f"mysql://root:root@{h}:{p}/app")
                elif p == "27017":
                    dbs.add(f"mongodb://{h}:{p}")
                elif p == "6379":
                    dbs.add(f"redis://{h}:{p}")
                else:
                    dbs.add(f"{h}:{p}")

        except Exception:
            pass
        return webs, dbs

    def _parse_workflow(self, file_path: str) -> Tuple[List[DiscoveredService], Set[str], Set[str]]:
        services: List[DiscoveredService] = []
        webs: Set[str] = set()
        dbs: Set[str] = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return services, webs, dbs

            jobs = data.get("jobs", {})
            if isinstance(jobs, dict):
                for jname, jdef in jobs.items():
                    if not isinstance(jdef, dict):
                        continue
                    job_services = jdef.get("services", {})
                    if isinstance(job_services, dict):
                        for sname, sdef in job_services.items():
                            if isinstance(sdef, dict):
                                img = sdef.get("image", "")
                                ports = [str(p) for p in sdef.get("ports", [])]
                                for db_key, (_, _, default_uri) in self.DB_IMAGE_PATTERNS.items():
                                    if db_key in img.lower() or db_key in sname.lower():
                                        dbs.add(default_uri)
                                        services.append(DiscoveredService(
                                            name=sname,
                                            service_type="database",
                                            image_or_source=img,
                                            ports=ports,
                                            connection_hint=default_uri
                                        ))
                                        break
        except Exception:
            pass
        return services, webs, dbs

    def _parse_package_json(self, file_path: str) -> Set[str]:
        webs: Set[str] = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                proxy = data.get("proxy")
                if proxy and isinstance(proxy, str):
                    webs.add(proxy)
                homepage = data.get("homepage")
                if homepage and isinstance(homepage, str) and homepage.startswith("http"):
                    webs.add(homepage)
        except Exception:
            pass
        return webs
