#!/usr/bin/env node
// Copyright Seaionl Inc. and CertPing contributors
// SPDX-License-Identifier: Apache-2.0

// Writes licenses/<image>/THIRD-PARTY-NOTICES.txt for every CertPing image from the dependencies
// that actually ship in it, and copies LICENSE, NOTICE and that file into each app's build
// context (apps/<app>/licenses/), where its Dockerfile picks them up.
//
// Run it through .github/scripts/third-party-notices.sh, which collects the inputs:
//   --maven <app>=<file>   output of `mvn dependency:list -DincludeScope=runtime
//                          -DoutputAbsoluteArtifactFilename=true` for a Java app
//   --pnpm <file>          output of `pnpm licenses list --prod --json` for apps/web
//   --out <dir>            write here instead of the repository (used by --check)
//
// Only Node.js built-ins are used. The output has no dates or absolute paths, so the same
// dependencies always give the same files.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const LICENSES = path.join(ROOT, 'licenses');
const TEXTS = path.join(LICENSES, 'texts');
const COMPONENTS = path.join(LICENSES, 'components');
const M2 = process.env.M2_REPO || path.join(os.homedir(), '.m2', 'repository');
const RULE = '='.repeat(100);
const LINE = '-'.repeat(100);

// ---------------------------------------------------------------------------------------------
// Arguments

const opts = { maven: {}, pnpm: null, out: null };
for (let i = 2; i < process.argv.length; i++) {
  const a = process.argv[i];
  if (a === '--maven') {
    const [app, file] = process.argv[++i].split('=');
    opts.maven[app] = file;
  } else if (a === '--pnpm') {
    opts.pnpm = process.argv[++i];
  } else if (a === '--out') {
    opts.out = process.argv[++i];
  } else {
    fail(`unknown argument ${a}`);
  }
}

function fail(msg) {
  console.error(`third-party-notices: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------------------------
// Licenses: names as projects write them, mapped to SPDX identifiers, and the texts we ship.

// Preference when a component offers a choice of licenses (dual or triple licensing). The first
// one offered in this order is the one CertPing elects to use and redistribute under.
const PREFERENCE = [
  'Apache-2.0', 'MIT', 'MIT-0', 'BSD-3-Clause', 'EDL-1.0', 'BSD-2-Clause', 'ISC', '0BSD',
  'CC0-1.0', 'EPL-2.0', 'MPL-2.0', 'LGPL-2.1-or-later', 'LGPL-3.0-or-later',
  'GPL-2.0-only WITH Classpath-exception-2.0',
];

// Files under licenses/texts/ with the full text of each license. LGPL-3.0 incorporates the
// GPL-3.0 by reference, so both go with it.
const TEXT_FILES = {
  'Apache-2.0': ['Apache-2.0.txt'],
  'MIT': ['MIT.txt'],
  'MIT-0': ['MIT-0.txt'],
  'ISC': ['ISC.txt'],
  '0BSD': ['0BSD.txt'],
  'BSD-2-Clause': ['BSD-2-Clause.txt'],
  'BSD-3-Clause': ['BSD-3-Clause.txt'],
  'EDL-1.0': ['EDL-1.0.txt'],
  'EPL-2.0': ['EPL-2.0.txt'],
  'CC0-1.0': ['CC0-1.0.txt'],
  'CC-BY-4.0': ['CC-BY-4.0.txt'],
  'MPL-2.0': ['MPL-2.0.txt'],
  'LGPL-3.0-or-later': ['LGPL-3.0.txt', 'GPL-3.0.txt'],
  'OFL-1.1': ['OFL-1.1.txt'],
  'PostgreSQL': ['PostgreSQL.txt'],
  'GPL-2.0-only WITH Classpath-exception-2.0': ['GPL-2.0-with-classpath-exception.txt'],
};

const TITLES = {
  'Apache-2.0': 'Apache License 2.0',
  'MIT': 'MIT License',
  'MIT-0': 'MIT No Attribution License',
  'ISC': 'ISC License',
  '0BSD': 'BSD Zero Clause License',
  'BSD-2-Clause': 'BSD 2-Clause License',
  'BSD-3-Clause': 'BSD 3-Clause License',
  'EDL-1.0': 'Eclipse Distribution License 1.0 (BSD-3-Clause)',
  'EPL-2.0': 'Eclipse Public License 2.0',
  'CC0-1.0': 'Creative Commons Zero 1.0 Universal',
  'CC-BY-4.0': 'Creative Commons Attribution 4.0 International',
  'MPL-2.0': 'Mozilla Public License 2.0',
  'LGPL-3.0-or-later': 'GNU Lesser General Public License 3.0 (with the GNU GPL 3.0 it incorporates)',
  'OFL-1.1': 'SIL Open Font License 1.1',
  'PostgreSQL': 'PostgreSQL License',
  'GPL-2.0-only WITH Classpath-exception-2.0': 'GNU General Public License 2.0 with the Classpath Exception',
};

function spdxFromName(name, url = '') {
  const n = name.toLowerCase().trim();
  const u = url.toLowerCase();
  if (n === 'mit-0') return 'MIT-0';
  if (/gpl2 w\/ cpe|classpath/.test(n)) return 'GPL-2.0-only WITH Classpath-exception-2.0';
  if (/lgpl|lesser general public/.test(n)) return 'LGPL-2.1-or-later';
  if (/apache/.test(n) || /apache\.org\/licenses\/license-2\.0/.test(u)) return 'Apache-2.0';
  if (/\bmit\b/.test(n) || /bouncy castle licen[cs]e/.test(n)) return 'MIT';
  if (/\bedl\b|eclipse distribution/.test(n)) return 'EDL-1.0';
  if (/\bepl\b|eclipse public/.test(n)) return /1\.0/.test(n) ? 'EPL-1.0' : 'EPL-2.0';
  if (/bsd-2|2-clause/.test(n)) return 'BSD-2-Clause';
  if (/bsd-3|3-clause|bsd new|new bsd|go license/.test(n)) return 'BSD-3-Clause';
  if (/cc0/.test(n)) return 'CC0-1.0';
  return null;
}

// Where a project's metadata is wrong or empty, what its jar and repository actually say.
const MAVEN_OVERRIDES = {
  // The 4.1.x POMs on Maven Central name a "Broadcom Foundation License" with no text or URL; the
  // jars carry the Apache License 2.0 (META-INF/LICENSE.txt), as does the project's repository.
  'org.springframework.session': {
    licenses: ['Apache-2.0'],
    note: 'POM metadata names a "Broadcom Foundation License"; the jar and the project ship the Apache License 2.0.',
  },
};

// Release tag formats of projects whose POM names no tag (or HEAD), to point at the source of the
// exact version shipped.
const SOURCE_TAGS = {
  'ch.qos.logback': (v) => `v_${v}`,
  'org.aspectj': (v) => `V${v.replaceAll('.', '_')}`,
  'jakarta.annotation': (v) => v,
  'jakarta.transaction': (v) => v,
};

// EPL-2.0 section 3.1(a): object code must come with a statement that the source code is available
// under the EPL and how to get it.
function eplSource(c) {
  if (!c.maven) fail(`${c.id} ${c.version}: EPL-2.0 needs a source statement; only Maven artifacts have one`);
  const { g, a, v, scm } = c.maven;
  const sourceTag = scm && scm.tag && scm.tag !== 'HEAD' ? scm.tag : SOURCE_TAGS[g]?.(v);
  if (!scm || !sourceTag) fail(`${c.id} ${c.version}: no source repository or tag for the EPL-2.0 statement; add it to SOURCE_TAGS`);
  const jar = `https://repo1.maven.org/maven2/${g.split('.').join('/')}/${a}/${v}/${a}-${v}-sources.jar`;
  return `Source code, available under the EPL-2.0: ${scm.url.replace(/\.git$/, '')} (tag ${sourceTag})\n      and ${jar}`;
}

function elect(ids) {
  const unique = [...new Set(ids)];
  if (unique.length <= 1) return { chosen: unique, offered: unique };
  const pick = PREFERENCE.find((p) => unique.includes(p));
  if (!pick) return { chosen: unique, offered: unique };
  return { chosen: [pick], offered: unique };
}

// ---------------------------------------------------------------------------------------------
// Text helpers

function normalize(text) {
  return text.replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '').replace(/^\n+|\n+$/g, '') + '\n';
}

function hash(text) {
  return crypto.createHash('sha256').update(text.replace(/\s+/g, ' ').trim()).digest('hex');
}

function readText(file) {
  return normalize(fs.readFileSync(file, 'utf8'));
}

// A license file that is just the standard text of a license whose full text we include anyway
// gives nothing to add. Apache LICENSE files sometimes put other terms before the license or
// append third-party terms after the appendix: keep those parts.
function extraBeyondStandard(text) {
  if (/Apache License\s+Version 2\.0, January 2004/.test(text) && /TERMS AND CONDITIONS/.test(text)) {
    const before = text.slice(0, text.search(/Apache License\s+Version 2\.0, January 2004/)).trim();
    const end = text.lastIndexOf('limitations under the License.');
    const rest = end >= 0 ? text.slice(end + 'limitations under the License.'.length).trim() : '';
    const kept = [before, rest].filter((part) => part.length > 200);
    return kept.length ? normalize(kept.join('\n\n[The Apache License 2.0 text, in section 6]\n\n')) : null;
  }
  if (/Eclipse Public License - v 2\.0/.test(text) && text.length > 10000) return null;
  if (/GNU (LESSER |LIBRARY )?GENERAL PUBLIC LICENSE\s+Version [23]/.test(text) && text.length > 15000) return null;
  return text;
}

// ---------------------------------------------------------------------------------------------
// Maven: the runtime classpath (what Spring Boot packs into BOOT-INF/lib), with each artifact's
// licenses from its POM (or the nearest parent that declares them) and the LICENSE and NOTICE
// files inside its jar.

function stripComments(xml) {
  return xml.replace(/<!--[\s\S]*?-->/g, '');
}

function tag(xml, name) {
  const m = xml.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`));
  return m ? m[1].trim() : null;
}

function pomFile(g, a, v) {
  return path.join(M2, ...g.split('.'), a, v, `${a}-${v}.pom`);
}

function pomInfo(g, a, v, depth = 0) {
  const file = pomFile(g, a, v);
  if (depth > 12 || !fs.existsSync(file)) return { licenses: null, url: null, scm: null };
  const xml = stripComments(fs.readFileSync(file, 'utf8'));
  const parent = tag(xml, 'parent');
  const own = parent ? xml.replace(/<parent>[\s\S]*?<\/parent>/, '') : xml;
  const block = tag(own, 'licenses');
  const licenses = block
    ? [...block.matchAll(/<license>([\s\S]*?)<\/license>/g)].map((m) => ({
        name: tag(m[1], 'name') || '',
        url: tag(m[1], 'url') || '',
      }))
    : null;
  // The project URL of the artifact itself, not of a dependency or plugin.
  const top = own.replace(/<(dependencies|dependencyManagement|build|profiles|licenses|developers|organization|scm|issueManagement|distributionManagement|mailingLists|ciManagement|repositories|pluginRepositories|reporting)>[\s\S]*?<\/\1>/g, '');
  let url = tag(top, 'url');
  if (url && url.includes('${')) url = null;
  const scmBlock = tag(own, 'scm');
  let scm = scmBlock ? { url: tag(scmBlock, 'url'), tag: tag(scmBlock, 'tag') } : null;
  if (scm && (!scm.url || scm.url.includes('${'))) scm = null;
  if ((!licenses || !url || !scm) && parent) {
    const up = pomInfo(tag(parent, 'groupId'), tag(parent, 'artifactId'), tag(parent, 'version'), depth + 1);
    // A parent of another project (org.eclipse.ee4j:project, for example) names its own repository.
    const sameProject = tag(parent, 'groupId') === g;
    return { licenses: licenses || up.licenses, url: url || up.url, scm: scm || (sameProject ? up.scm : null) };
  }
  return { licenses, url, scm };
}

function jarEntries(jar) {
  try {
    return execFileSync('unzip', ['-Z1', jar], { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\n');
  } catch {
    return [];
  }
}

function jarText(jar, entry) {
  const escaped = entry.replace(/[[\]*?\\]/g, '\\$&');
  return normalize(execFileSync('unzip', ['-p', jar, escaped], { encoding: 'utf8', maxBuffer: 16 << 20 }));
}

function parseMavenList(file) {
  const out = [];
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (line.includes('(optional)')) continue; // Spring Boot does not package optional dependencies
    const m = line.match(/^\s+([^:\s]+):([^:\s]+):([^:\s]+):(?:([^:\s]+):)?([^:\s]+):(compile|runtime):(\/\S+?\.jar)/);
    if (!m) continue;
    const [, g, a, , classifier, v, , jar] = m;
    out.push({ g, a, v, classifier, jar });
  }
  if (out.length === 0) fail(`no runtime dependencies found in ${file}`);
  return out;
}

function mavenComponents(file) {
  const components = [];
  for (const d of parseMavenList(file)) {
    const info = pomInfo(d.g, d.a, d.v);
    const override = MAVEN_OVERRIDES[`${d.g}:${d.a}`] || MAVEN_OVERRIDES[d.g];
    let ids;
    if (override) {
      ids = override.licenses;
    } else {
      if (!info.licenses || info.licenses.length === 0) fail(`${d.g}:${d.a}:${d.v} declares no license; add an override`);
      ids = info.licenses.map((l) => {
        const id = spdxFromName(l.name, l.url);
        if (!id) fail(`${d.g}:${d.a}:${d.v}: unknown license "${l.name}"; map it in spdxFromName`);
        return id;
      });
    }
    const files = [];
    for (const entry of jarEntries(d.jar)) {
      // Top-level and META-INF legal files, and the ones jars bundle for code they shade or embed
      // under META-INF/license(s)/.
      const legal = /^(META-INF\/)?[^/]*(LICEN[CS]E|NOTICE|COPYING|COPYRIGHT)[^/]*$/i.test(entry)
        || /^META-INF\/licen[cs]es?\/./i.test(entry);
      if (!legal) continue;
      if (/\.(class|html?|xml)$/i.test(entry) || entry.endsWith('/')) continue;
      files.push({ kind: /NOTICE/i.test(path.basename(entry)) ? 'notice' : 'license', name: entry, text: jarText(d.jar, entry) });
    }
    components.push({
      id: `${d.g}:${d.a}${d.classifier ? ':' + d.classifier : ''}`,
      version: d.v,
      url: info.url,
      licenses: ids,
      note: override ? override.note : null,
      maven: { g: d.g, a: d.a, v: d.v, scm: info.scm },
      files,
    });
  }
  return components;
}

// ---------------------------------------------------------------------------------------------
// pnpm: the production dependency tree of apps/web, each package's license field and the
// LICENSE and NOTICE files in its directory.

// The images run on Linux (glibc) for amd64 and arm64. Packages with native code are installed
// for the machine that runs this script; report the Linux variants the image installs instead
// (same version and license, built from the same source).
const PLATFORM_PACKAGES = [
  { re: /^(@img\/sharp(?:-libvips)?)-(darwin|win32|linux|linuxmusl)-[a-z0-9]+$/, linux: ['linux-x64', 'linux-arm64'] },
  { re: /^(@next\/swc)-(darwin|win32|linux)-[a-z0-9-]+$/, linux: ['linux-x64-gnu', 'linux-arm64-gnu'] },
];

// Optional packages that only install on macOS and so are never in the Linux images.
const MACOS_ONLY = new Set(['fsevents']);

function splitExpression(expr) {
  const e = expr.replace(/[()]/g, '').trim();
  if (/ OR /.test(e)) return { op: 'OR', ids: e.split(/ OR /).map((s) => s.trim()) };
  return { op: 'AND', ids: e.split(/ AND /).map((s) => s.trim()) };
}

function pnpmComponents(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  const components = [];
  const seen = new Set();
  for (const [license, pkgs] of Object.entries(data)) {
    for (const p of pkgs) {
      if (MACOS_ONLY.has(p.name)) continue;
      let names = [p.name];
      for (const pp of PLATFORM_PACKAGES) {
        const m = p.name.match(pp.re);
        if (m) names = pp.linux.map((suffix) => `${m[1]}-${suffix}`);
      }
      const files = [];
      for (const dir of p.paths) {
        for (const f of fs.readdirSync(dir).sort()) {
          if (!/^(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT)([.\-_].*)?$/i.test(f)) continue;
          const full = path.join(dir, f);
          if (!fs.statSync(full).isFile()) continue;
          files.push({ kind: /NOTICE/i.test(f) ? 'notice' : 'license', name: f, text: readText(full) });
        }
      }
      const expr = splitExpression(license);
      for (const id of expr.ids) if (!TEXT_FILES[id]) fail(`${p.name}: no text for license ${id}; add licenses/texts and TEXT_FILES`);
      const { chosen, offered } = expr.op === 'OR' ? elect(expr.ids) : { chosen: expr.ids, offered: expr.ids };
      for (const name of names) {
        // Linux installs both the glibc and musl variants of some packages; both map to one entry.
        const key = `${name}@${p.versions.join(',')}`;
        if (seen.has(key)) continue;
        seen.add(key);
        components.push({
          id: name,
          version: p.versions.join(', '),
          url: p.homepage || null,
          author: p.author || null,
          licenses: offered,
          chosen,
          and: expr.op === 'AND',
          note: PACKAGE_NOTES[name] || null,
          dirs: p.paths,
          files,
        });
      }
    }
  }
  return components;
}

// ---------------------------------------------------------------------------------------------
// Go modules compiled into the Caddy binary of the all-in-one: modules.txt is what `caddy
// build-info` prints, and each <module>@<version>/ holds the legal files of that module's source
// at that version (licenses/README.md says how they were collected).

const CADDY = path.join(COMPONENTS, 'caddy-2.8.4');

// Every license a module's license file states; some cover parts of a module with other terms.
function goLicenseIds(text, where) {
  const ids = [];
  if (/CC0 1\.0 Universal/.test(text)) ids.push('CC0-1.0');
  if (/Apache License,?\s+Version 2\.0/i.test(text)) ids.push('Apache-2.0');
  if (/Mozilla Public License,?\s+(Version|v\.?)\s*2\.0/i.test(text)) ids.push('MPL-2.0');
  if (/Permission is hereby granted, free of charge/i.test(text)) ids.push('MIT');
  if (/Permission to use, copy, modify, and(\/or)? distribute this software for any\s+purpose/i.test(text)) ids.push('ISC');
  if (/Redistribution and use in source and binary forms/i.test(text)) {
    ids.push(/Neither the name|endorse or promote/i.test(text) ? 'BSD-3-Clause' : 'BSD-2-Clause');
  }
  if (ids.length === 0) fail(`${where}: cannot tell its license; add the case to goLicenseIds`);
  return ids;
}

function goModuleZip(mod, version) {
  const escaped = mod.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
  return `https://proxy.golang.org/${escaped}/@v/${version}.zip`;
}

function caddyModules() {
  const [first, ...rest] = readText(path.join(CADDY, 'modules.txt')).trim().split('\n');
  const toolchain = first.match(/^Go toolchain (go\S+)$/);
  if (!toolchain) fail('caddy-2.8.4/modules.txt must start with "Go toolchain <version>"');
  const modules = [['go', toolchain[1]], ...rest.map((l) => l.trim().split(/\s+/))];
  return modules.map(([mod, version]) => {
    const dir = path.join(CADDY, `${mod}@${version}`);
    if (!fs.existsSync(dir)) fail(`no legal files for Go module ${mod} ${version}: add ${path.relative(ROOT, dir)}/`);
    const files = fs.readdirSync(dir, { recursive: true }).sort()
      .filter((rel) => fs.statSync(path.join(dir, rel)).isFile())
      .map((rel) => ({ kind: /NOTICE/i.test(path.basename(rel)) ? 'notice' : 'license', name: rel, text: readText(path.join(dir, rel)) }));
    const top = files.filter((f) => !f.name.includes(path.sep) && /^(LICEN[CS]E|COPYING)/i.test(f.name));
    if (top.length === 0) fail(`Go module ${mod} ${version} has no license file`);
    const isGo = mod === 'go';
    return {
      id: isGo ? 'Go standard library and runtime' : mod,
      version,
      url: isGo ? `https://github.com/golang/go/tree/${version}` : goModuleZip(mod, version),
      licenses: [...new Set(top.flatMap((f) => goLicenseIds(f.text, `${mod} ${version} (${f.name})`)))],
      and: true,
      files,
    };
  });
}

// ---------------------------------------------------------------------------------------------
// Components that are part of an image but not dependencies of the application: the runtime it
// runs on and the programs the all-in-one adds. `texts` names the license texts to append (the
// default is `licenses`); `files` are files under licenses/components/ to include verbatim.

// The base images the Dockerfiles pin by digest. The versions written below for the components
// they bring (and the source locations in section 7) were read from these images; the generator
// fails when a Dockerfile pins another digest, so that they are updated with it.
const BASE_IMAGES = [
  {
    image: 'registry.access.redhat.com/ubi9/openjdk-25-runtime',
    tag: '1.24-3.1793323806',
    digest: 'sha256:2ddacad5332f4e481353668f210623f7e7420f1561515f5686e5abd33cd6d38f',
    dockerfiles: ['apps/server/Dockerfile', 'apps/agent/Dockerfile', 'apps/notifier/Dockerfile'],
  },
  {
    image: 'registry.access.redhat.com/ubi10/nodejs-24',
    tag: '10.3-1795423475',
    digest: 'sha256:f4748b252f0f7353e0f617625ebcba5768e847dde6aaa4b116ac6e2a954c54b0',
    dockerfiles: ['apps/web/Dockerfile'],
  },
  {
    image: 'eclipse-temurin',
    tag: '25-jre',
    digest: 'sha256:ecdc0adb37bde1a281c4d245a3cd535004b1fc8322d560f5b09463b248c81df0',
    dockerfiles: ['deploy/all-in-one/Dockerfile'],
  },
  {
    image: 'caddy',
    tag: '2.8.4-alpine',
    digest: 'sha256:af32e97399febea808609119bb21544d0265c58a02836576e32a2d082c262c17',
    dockerfiles: ['deploy/all-in-one/Dockerfile'],
  },
  {
    image: 'node',
    tag: '24.13.0-bookworm-slim',
    digest: 'sha256:4660b1ca8b28d6d1906fd644abe34b2ed81d15434d26d845ef0aced307cf4b6f',
    dockerfiles: ['deploy/all-in-one/Dockerfile'],
  },
];

for (const b of BASE_IMAGES) {
  const pins = (line) => line.includes(`@${b.digest}`) && (line.includes(`${b.image}@`) || line.includes(`${b.image}:`));
  for (const f of b.dockerfiles) {
    if (!fs.readFileSync(path.join(ROOT, f), 'utf8').split('\n').some(pins)) {
      fail(`${f} no longer pins ${b.image}@${b.digest}: update BASE_IMAGES and the versions read from it`);
    }
  }
}

function baseImage(image) {
  const b = BASE_IMAGES.find((x) => x.image === image);
  return `${b.image}:${b.tag} (${b.digest})`;
}

const OTEL_AGENT = {
  title: 'OpenTelemetry Java agent',
  version: '2.32.0',
  licenses: ['Apache-2.0'],
  where: '/app/otel/opentelemetry-javaagent.jar',
  body: `Copyright The OpenTelemetry Authors. Source: https://github.com/open-telemetry/opentelemetry-java-instrumentation
The jar has no top-level NOTICE file. It lists the libraries it bundles, with their licenses, in
META-INF/licenses/licenses.md inside the jar and carries their LICENSE and NOTICE files under
META-INF/licenses/. The NOTICE files and the extra license files it bundles follow.`,
  files: ['opentelemetry-javaagent-2.32.0-notices.txt'],
};

const UBI_OPENJDK = {
  title: 'Red Hat build of OpenJDK 25 on Red Hat Universal Base Image 9 (base image)',
  version: '25.0.5 (package java-25-openjdk 25.0.5.0.8-1.0.el9)',
  licenses: ['GPL-2.0-only WITH Classpath-exception-2.0'],
  where: 'registry.access.redhat.com/ubi9/openjdk-25-runtime',
  body: `CertPing runs on this JDK and does not modify it; the Classpath Exception lets the application
use it under the application's own license. The JDK's license and the notices of the libraries it
contains are in /usr/lib/jvm/java-25-openjdk/legal/ in this image, and the licenses of the
operating system packages are in /usr/share/licenses/. The base image is redistributed under the
Red Hat Universal Base Image End User License Agreement:
https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf
Source code: see section 7.`,
};

function nodeRuntime(version, label, where, extra) {
  return {
    title: 'Node.js',
    version: label,
    licenses: ['MIT'],
    texts: [],
    where,
    body: `Copyright Node.js contributors. Source: https://github.com/nodejs/node (tag v${version})
${extra}The Node.js license, which also gives the licenses of the libraries Node.js bundles, follows.`,
    files: [`nodejs-${version}-LICENSE.txt`],
  };
}

const UBI_NODE = nodeRuntime(
  '24.22.1',
  '24.22.1 (package nodejs24 24.22.1-3.el10_2)',
  'registry.access.redhat.com/ubi10/nodejs-24 (base image)',
  `The base image is redistributed under the Red Hat Universal Base Image End User License Agreement:
https://www.redhat.com/licenses/EULA_Red_Hat_Universal_Base_Image_English_20190422.pdf
The licenses of its operating system packages are in /usr/share/licenses/.
`,
);

const FONTS = [
  {
    title: 'Geist and Geist Mono fonts',
    version: '1.200 (variable)',
    licenses: ['OFL-1.1'],
    texts: [],
    where: 'served by the web app from /_next/static/media/',
    body: `The font files carry no copyright or license metadata in their name tables; the upstream project
(https://github.com/vercel/geist-font) releases them under the SIL Open Font License 1.1 with the
notice below. CertPing bundles the fonts unmodified and does not sell them by themselves.`,
    files: ['font-geist-OFL.txt'],
  },
  {
    title: 'Plus Jakarta Sans font',
    version: '2.071 (variable)',
    licenses: ['OFL-1.1'],
    texts: [],
    where: 'served by the web app from /_next/static/media/',
    body: `Font metadata: "Copyright 2020 The Plus Jakarta Sans Project Authors
(https://github.com/tokotype/PlusJakartaSans)"; "This Font Software is licensed under the SIL Open
Font License, Version 1.1". CertPing bundles the font unmodified and does not sell it by itself.`,
    files: ['font-plus-jakarta-sans-OFL.txt'],
  },
];

// Code copied into the repository from another project and changed there, not installed as a package.
const VENDORED = [
  {
    title: 'shadcn/ui components',
    version: 'copied into the source and changed (not a package)',
    licenses: ['MIT'],
    where: 'apps/web/src/components/ui, built into the web app',
    body: `The UI components in apps/web/src/components/ui started from shadcn/ui
(https://ui.shadcn.com, source https://github.com/shadcn-ui/ui) and were changed for CertPing.

Copyright (c) 2023 shadcn. Licensed under the MIT License, whose text is in the license texts below.`,
  },
];

// Notes printed with a package in the libraries list.
const PACKAGE_NOTES = {
  'caniuse-lite': 'Attribution: contains data from Can I use (https://caniuse.com) by Alexis Deveria, licensed under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). The data is used unmodified.',
};

// libvips, the LGPL library sharp loads, gets its own section with the source, the replacement
// terms and the legal files of every library bundled into it, built from the installed
// @img/sharp-libvips package. The legal files of each bundled library, from its source at the
// version in versions.json, are in licenses/components/sharp-libvips-<version>/<library>-<version>/.
function libvipsSection(web) {
  const pkg = web.find((c) => c.id.startsWith('@img/sharp-libvips-'));
  if (!pkg) return null;
  const dir = pkg.dirs[0];
  const versions = JSON.parse(fs.readFileSync(path.join(dir, 'versions.json'), 'utf8'));
  const readme = fs.readFileSync(path.join(dir, 'README.md'), 'utf8');
  const licensing = (readme.split('## Licensing')[1] || '').trim().replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)');
  const pkgVersion = pkg.version;
  const libs = Object.entries(versions).map(([k, v]) => `  ${k.padEnd(14)} ${v}`).join('\n');

  const legal = new Map(); // hash -> { text, from: [] }
  const base = path.join(COMPONENTS, `sharp-libvips-${pkgVersion}`);
  for (const [lib, version] of Object.entries(versions)) {
    const libDir = path.join(base, `${lib}-${version}`);
    if (!fs.existsSync(libDir)) fail(`no legal files for ${lib} ${version} in libvips: add ${path.relative(ROOT, libDir)}/`);
    for (const f of fs.readdirSync(libDir, { recursive: true }).sort()) {
      if (!fs.statSync(path.join(libDir, f)).isFile()) continue;
      const text = extraBeyondStandard(readText(path.join(libDir, f)));
      if (!text) continue;
      const key = hash(text);
      if (!legal.has(key)) legal.set(key, { text, from: [] });
      legal.get(key).from.push(`${lib} ${version} (${f})`);
    }
  }
  const legalFiles = [...legal.values()]
    .map((e) => `\n${LINE}\nFrom: ${e.from.join('\n      ')}\n${LINE}\n${e.text}`)
    .join('');

  return {
    vipsVersion: versions.vips,
    pkgVersion,
    title: 'libvips and the libraries it bundles (used by sharp)',
    version: `libvips ${versions.vips} in @img/sharp-libvips-linux-x64 and @img/sharp-libvips-linux-arm64 ${pkgVersion}`,
    licenses: ['LGPL-2.1-or-later (used under LGPL-3.0)'],
    texts: ['LGPL-3.0-or-later', 'MPL-2.0'],
    where: 'node_modules/@img/sharp-libvips-linux-<arch>/lib/',
    body: `The web app optimises images with sharp (Apache-2.0), which loads the prebuilt shared library
libvips-cpp.so.${versions.vips} and the libraries it depends on at run time. libvips is licensed
under the GNU Lesser General Public License 2.1 or later. CertPing uses it, and the bundled
libraries licensed under the LGPL, as sharp-libvips does: under the LGPL 3.0, which each of
their licenses allows.

Source code: libvips ${versions.vips}: https://github.com/libvips/libvips (tag v${versions.vips}).
The build scripts, the patches they apply and the exact versions of every bundled library are at
https://github.com/lovell/sharp-libvips (tag v${pkgVersion}). CertPing does not modify libvips or
the libraries it bundles.

You may replace the libvips library in this image with a version you build or modify yourself,
for example by replacing the files in node_modules/@img/sharp-libvips-linux-<arch>/lib/ with a
compatible build; sharp loads it dynamically, so no part of CertPing has to be rebuilt.

This software is based in part on the work of the Independent JPEG Group.

Portions of this software are copyright © 2026 The FreeType Project (https://freetype.org). All
rights reserved.

cairo ${versions.cairo} is offered under the GNU LGPL 2.1 or the Mozilla Public License 1.1. CertPing uses
it under the Mozilla Public License 2.0, as section 6.2 of the MPL 1.1 allows. Its source code:
https://cairographics.org/releases/cairo-${versions.cairo}.tar.xz

Bundled library versions:
${libs}

Licensing, from the package README:
${licensing}

The copyright and license files of libvips and the bundled libraries follow, from the source of
each at the version above. Files that are essentially the text of the GNU LGPL or GPL are not
repeated; the LGPL 3.0 and the GPL 3.0 it incorporates are in section 6.
${legalFiles}`,
  };
}

const ALL_IN_ONE = [
  {
    title: 'Ubuntu 26.04 LTS packages, Eclipse Temurin base image',
    version: 'eclipse-temurin:25-jre (Ubuntu 26.04)',
    licenses: ['various'],
    texts: [],
    where: '/usr/share/doc/<package>/copyright',
    body: `The image is built on eclipse-temurin:25-jre, which is Ubuntu 26.04 LTS, and adds Ubuntu's
postgresql-18, valkey-server, supervisor, curl, openssl, gosu and their dependencies. The
copyright and license of every Ubuntu package is in /usr/share/doc/<package>/copyright in this
image. Source code: see section 7.`,
  },
  {
    title: 'Eclipse Temurin OpenJDK 25 JRE',
    version: '25.0.5+8',
    licenses: ['GPL-2.0-only WITH Classpath-exception-2.0'],
    where: '/opt/java/openjdk',
    body: `The Java runtime of the server, agent and notifier. CertPing runs on it and does not modify it; the
Classpath Exception lets the application use it under the application's own license. The
notices of the libraries the JRE contains are in /opt/java/openjdk/legal/.
Source code: see section 7.`,
  },
  {
    title: 'PostgreSQL',
    version: '18 (Ubuntu package postgresql-18)',
    licenses: ['PostgreSQL'],
    where: '/usr/lib/postgresql/18',
    body: 'Source code: https://www.postgresql.org/ftp/source/ and apt-get source postgresql-18.',
  },
  {
    title: 'Valkey',
    version: '9.0.4 (Ubuntu package valkey-server)',
    licenses: ['BSD-3-Clause'],
    texts: [],
    where: '/usr/bin/valkey-server',
    body: 'The Redis-compatible store the server uses. Source code: https://github.com/valkey-io/valkey (tag 9.0.4). Its license file follows.',
    files: ['valkey-COPYING.txt'],
  },
  {
    title: 'Caddy',
    version: '2.8.4',
    licenses: ['Apache-2.0'],
    where: '/usr/local/bin/caddy (from the caddy:2.8.4-alpine image)',
    body: `Copyright 2015 Matthew Holt and The Caddy Authors. Source: https://github.com/caddyserver/caddy
(tag v2.8.4). Caddy is a Go program: the binary contains the Go standard library and runtime and
the Go modules listed in section 2 under "Go modules in /usr/local/bin/caddy", at the versions
\`caddy build-info\` prints from it. Their license, NOTICE and patent files are in sections 4 and
5 and the license texts in section 6; the source code of each module at that version is at the
address listed with it.`,
  },
  nodeRuntime('24.13.0', '24.13.0', '/usr/local/bin/node (from the node:24.13.0-bookworm-slim image)', ''),
  {
    title: 'supervisor and gosu',
    version: 'supervisor 4.3.0, gosu 1.19 (Ubuntu packages)',
    licenses: ['various'],
    texts: [],
    where: '/usr/bin/supervisord, /usr/sbin/gosu',
    body: `supervisor runs the services; gosu changes user at start. Their licenses (supervisor: a BSD-derived
license; gosu: Apache 2.0) are in /usr/share/doc/supervisor/copyright and
/usr/share/doc/gosu/copyright.`,
  },
];

// ---------------------------------------------------------------------------------------------
// Source code of the GPL and LGPL components of each image (section 7): a written offer of it
// (the form of GPL-2.0 section 3(b) and LGPL-2.1 section 6(c)) and where upstream publishes it.

const UBI9_SOURCE = {
  components: [
    'OpenJDK 25.0.5, the Red Hat build in package java-25-openjdk 25.0.5.0.8-1.0.el9 (GPL-2.0 with\n    the Classpath Exception)',
    'the operating system packages of the base image licensed under the GPL or the LGPL; list them\n    with: rpm -qa --qf \'%{NAME} %{VERSION}-%{RELEASE}: %{LICENSE}\\n\'',
  ],
  locations: [
    `Base image: ${baseImage('registry.access.redhat.com/ubi9/openjdk-25-runtime')}`,
    'OpenJDK: https://github.com/openjdk/jdk25u (tag jdk-25.0.5+8), from which Red Hat builds the\n    source RPM java-25-openjdk-25.0.5.0.8-1.0.el9.src.rpm',
    'Base image packages: the UBI 9 source repositories,\n    https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/<arch>/{baseos,appstream}/source/SRPMS/\n    (they keep only the current build of each package; the builds in this image are covered by\n    the offer above)',
  ],
};

function libvipsSource(libvips) {
  if (!libvips) fail('sharp-libvips is missing from the web app dependencies');
  return {
    component: 'libvips and the libraries bundled in it that are licensed under the LGPL (section 1)',
    location: `libvips and its bundled libraries: https://github.com/libvips/libvips (tag v${libvips.vipsVersion}),\n    and the build scripts and patches of https://github.com/lovell/sharp-libvips (tag v${libvips.pkgVersion}),\n    which name the source archive of each bundled library`,
  };
}

function webSource(libvips) {
  const vips = libvipsSource(libvips);
  const image = BASE_IMAGES.find((b) => b.image === 'registry.access.redhat.com/ubi10/nodejs-24');
  return {
    components: [
      'the operating system packages of the base image licensed under the GPL or the LGPL; list them\n    with: rpm -qa --qf \'%{NAME} %{VERSION}-%{RELEASE}: %{LICENSE}\\n\'',
      vips.component,
    ],
    locations: [
      `Base image: ${baseImage(image.image)}`,
      `Base image packages: the source RPMs of the image, published as the source image\n    ${image.image}:${image.tag}-source`,
      vips.location,
    ],
  };
}

function allInOneSource(libvips) {
  const vips = libvipsSource(libvips);
  return {
    components: [
      'Eclipse Temurin OpenJDK 25.0.5+8 JRE (GPL-2.0 with the Classpath Exception)',
      'the Ubuntu packages in the image licensed under the GPL or the LGPL; list them with:\n    dpkg-query -W -f \'${source:Package} ${source:Version}\\n\' and see /usr/share/doc/<package>/copyright',
      vips.component,
    ],
    locations: [
      `Base image: ${baseImage('eclipse-temurin')}, Ubuntu 26.04 LTS`,
      'Temurin JRE: https://github.com/adoptium/jdk25u (tag jdk-25.0.5+8_adopt), from OpenJDK\n    https://github.com/openjdk/jdk25u (tag jdk-25.0.5+8)',
      'Ubuntu packages: the Ubuntu 26.04 LTS source packages, https://launchpad.net/ubuntu/+source/<package>\n    (apt-get source <package>=<version>)',
      vips.location,
    ],
  };
}

function sourceSection(source) {
  const list = (items) => items.map((i) => `  - ${i}`).join('\n');
  return `Some components of this image are licensed under a version of the GNU General Public License
(GPL) or the GNU Lesser General Public License (LGPL):

${list(source.components)}

Written offer: for at least three years after Seaionl Inc. last distributes this image, Seaionl
Inc. will give any third party, on request, a complete machine-readable copy of the corresponding
source code of these components, to be distributed under the terms of the license of each
component, on a medium customarily used for software interchange, for a charge no more than its
cost of physically performing source distribution. Send requests to legal@certping.com, naming
the image and its version or digest. This offer is valid to anyone in receipt of this
information.

Where upstream publishes the source:

${list(source.locations)}
`;
}

// ---------------------------------------------------------------------------------------------
// Rendering

function heading(n, title) {
  return `\n${RULE}\n${n}. ${title}\n${RULE}\n`;
}

function licenseLabel(c) {
  const chosen = c.chosen || elect(c.licenses).chosen;
  if (c.licenses.length > 1 && !c.and) {
    return `${chosen.join(' AND ')} (elected from ${c.licenses.join(' OR ')})`;
  }
  return c.licenses.join(' AND ');
}

function render({ title, intro, runtime, groups, source }) {
  const out = [];
  const usedTexts = new Set();
  const notices = new Map(); // hash -> { text, from: Set }
  const licenseFiles = new Map();
  const elections = [];

  const addFile = (map, text, from) => {
    const key = hash(text);
    if (!map.has(key)) map.set(key, { text, from: new Set() });
    map.get(key).from.add(from);
  };

  out.push(`${title}\n${'='.repeat(title.length)}\n`);
  out.push(intro.trim() + '\n');

  // 1. Runtime components
  out.push(heading(1, 'Components of the image besides the application'));
  for (const c of runtime) {
    out.push(`\n${LINE}\n${c.title}\n  Version: ${c.version}\n  License: ${c.licenses.join(' AND ')}\n  Location: ${c.where}\n\n${c.body.trim()}\n`);
    for (const id of c.texts ?? c.licenses) usedTexts.add(id);
    for (const f of c.files || []) out.push(`\n${readText(path.join(COMPONENTS, f))}`);
  }

  // 2. Libraries
  out.push(heading(2, 'Libraries'));
  out.push(`Each library with its version and the license under which CertPing uses and redistributes it.
Where a library is offered under a choice of licenses, the elected license is named first; see
section 3. Copyright notices are as published by each project; the ones its package carries are
reproduced in sections 4 and 5, and the full license texts are in section 6.\n`);
  for (const g of groups) {
    out.push(`\n${g.heading} (${g.components.length})\n${'-'.repeat(g.heading.length + String(g.components.length).length + 3)}\n`);
    const sorted = [...g.components].sort((a, b) => a.id.localeCompare(b.id) || a.version.localeCompare(b.version));
    for (const c of sorted) {
      const chosen = c.chosen || (c.and ? c.licenses : elect(c.licenses).chosen);
      for (const id of chosen) {
        if (!TEXT_FILES[id]) fail(`${c.id}: no text for elected license ${id}`);
        usedTexts.add(id);
      }
      if (c.licenses.length > 1 && !c.and) elections.push({ c, chosen });
      const source = chosen.includes('EPL-2.0') ? `\n    ${eplSource(c)}` : '';
      out.push(`${c.id} ${c.version}\n    ${licenseLabel(c)}${c.url ? `\n    ${c.url}` : ''}${source}${c.note ? `\n    Note: ${c.note}` : ''}\n`);
      for (const f of c.files) {
        const from = `${c.id} ${c.version} (${f.name})`;
        if (f.kind === 'notice') {
          if (f.text.trim()) addFile(notices, f.text, from);
        } else {
          const extra = extraBeyondStandard(f.text);
          if (extra) addFile(licenseFiles, extra, from);
        }
      }
      if (c.author && !c.files.some((f) => f.kind === 'license')) {
        addFile(licenseFiles, `${licenseLabel(c)}. The package ships no license file; its author is given as: ${c.author}\n`, `${c.id} ${c.version}`);
      }
    }
  }

  // 3. Elections
  out.push(heading(3, 'License elections'));
  out.push(`These components are offered under a choice of licenses. CertPing elects, and redistributes them
under, the license named.\n\n`);
  const seen = new Set();
  for (const { c, chosen } of elections.sort((a, b) => a.c.id.localeCompare(b.c.id))) {
    const key = `${c.id} ${c.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(`- ${key}: ${chosen.join(' AND ')}, of ${c.licenses.join(' OR ')}\n`);
  }
  if (seen.size === 0) out.push('None of the components in this image needs an election.\n');

  const dump = (n, name, map, what) => {
    out.push(heading(n, name));
    out.push(`${what}\n`);
    const entries = [...map.values()].sort((a, b) => [...a.from].sort()[0].localeCompare([...b.from].sort()[0]));
    for (const e of entries) {
      out.push(`\n${LINE}\nFrom: ${[...e.from].sort().join('\n      ')}\n${LINE}\n${e.text}`);
    }
  };
  dump(4, 'NOTICE files', notices, 'The NOTICE files the libraries carry, reproduced as section 4(d) of the Apache License 2.0 requires.');
  dump(5, 'Copyright and license statements from the libraries', licenseFiles,
    'License files the libraries carry, where they add copyright notices or terms to the standard texts in section 6.');

  // 6. License texts
  out.push(heading(6, 'License texts'));
  for (const id of [...usedTexts].filter((id) => TEXT_FILES[id]).sort()) {
    for (const f of TEXT_FILES[id]) {
      out.push(`\n${LINE}\n${TITLES[id]}${TEXT_FILES[id].length > 1 ? ` (${f.replace('.txt', '')})` : ''}\n${LINE}\n${readText(path.join(TEXTS, f))}`);
    }
  }

  // 7. Source code
  out.push(heading(7, 'Source code'));
  out.push(sourceSection(source));
  return out.join('');
}

// ---------------------------------------------------------------------------------------------
// The images

function intro(image, location) {
  return `This file lists the third-party software in the ${image} image and the notices and license texts
that come with it. It is generated by .github/scripts/third-party-notices.sh from the dependencies the
image ships; do not edit it by hand.

CertPing is Copyright 2024-2026 Seaionl Inc. and is licensed under the Apache License 2.0 (LICENSE,
beside this file). Third-party components remain under their own licenses, given below. In the
image these files are in ${location}. Source code for CertPing:
https://github.com/certping-labs/certping. Section 7 offers the source code of the components
licensed under the GPL or the LGPL.`;
}

const JAVA_APPS = {
  server: 'certping-server',
  agent: 'certping-agent',
  notifier: 'certping-notifier',
};

const java = {};
for (const [app, file] of Object.entries(opts.maven)) {
  if (!JAVA_APPS[app]) fail(`unknown Java app ${app}`);
  java[app] = mavenComponents(file);
}
const web = opts.pnpm ? pnpmComponents(opts.pnpm) : null;
for (const app of Object.keys(JAVA_APPS)) if (!java[app]) fail(`--maven ${app}=<file> is required`);
if (!web) fail('--pnpm <file> is required');

const libvips = libvipsSection(web);
const docs = {};
for (const [app, image] of Object.entries(JAVA_APPS)) {
  docs[app] = render({
    title: `${image}: third-party notices`,
    intro: intro(image, '/licenses/certping/'),
    runtime: [UBI_OPENJDK, OTEL_AGENT],
    groups: [{ heading: `Java libraries in /app/app.jar (BOOT-INF/lib)`, components: java[app] }],
    source: UBI9_SOURCE,
  });
}
docs.web = render({
  title: 'certping-web: third-party notices',
  intro: intro('certping-web', '/licenses/certping/'),
  runtime: [UBI_NODE, ...FONTS, ...VENDORED, libvips].filter(Boolean),
  groups: [{ heading: 'npm packages (production dependencies of apps/web)', components: web }],
  source: webSource(libvips),
});

// The all-in-one carries the four applications' jars and web app (without the OpenTelemetry
// agent, which only the separate images include) plus its own runtime.
docs['all-in-one'] = render({
  title: 'certping (all-in-one): third-party notices',
  intro: intro('certping all-in-one', '/licenses/certping/'),
  runtime: [...ALL_IN_ONE, ...FONTS, ...VENDORED, libvips].filter(Boolean),
  groups: [
    { heading: 'Java libraries in /opt/certping/server.jar', components: java.server },
    { heading: 'Java libraries in /opt/certping/agent.jar', components: java.agent },
    { heading: 'Java libraries in /opt/certping/notifier.jar', components: java.notifier },
    { heading: 'npm packages in /opt/certping/web', components: web },
    { heading: 'Go modules in /usr/local/bin/caddy', components: caddyModules() },
  ],
  source: allInOneSource(libvips),
});

// ---------------------------------------------------------------------------------------------
// Output: licenses/<image>/THIRD-PARTY-NOTICES.txt, and LICENSE, NOTICE and that file in each
// app's build context (the separate images are built from apps/<app>).

const outRoot = opts.out ? path.resolve(opts.out) : ROOT;
function write(rel, text) {
  const file = path.join(outRoot, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

const license = fs.readFileSync(path.join(ROOT, 'LICENSE'), 'utf8');
const notice = fs.readFileSync(path.join(ROOT, 'NOTICE'), 'utf8');
write('licenses/LICENSE', license);
write('licenses/NOTICE', notice);
for (const [name, text] of Object.entries(docs)) {
  write(`licenses/${name}/THIRD-PARTY-NOTICES.txt`, text);
  if (name === 'all-in-one') continue;
  write(`apps/${name}/licenses/LICENSE`, license);
  write(`apps/${name}/licenses/NOTICE`, notice);
  write(`apps/${name}/licenses/THIRD-PARTY-NOTICES.txt`, text);
  console.log(`${name}: ${text.split('\n').length} lines`);
}
console.log(`all-in-one: ${docs['all-in-one'].split('\n').length} lines`);
