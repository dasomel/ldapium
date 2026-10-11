#!/usr/bin/env python3
"""Guard: the DRILL-ONLY Go build tag `machinewritedrill` must never reach a default or published build.

Change package docs/changes/machine-write-scope, T-022. The tag registers the five machine write
operations (ui/backend/internal/httpapi/machine_write_drill.go) so the emergency-block drill can run the
real pipeline before T-013 opens writes. Production and release builds must stay closed. This guard fails if
the tag, a non-empty GO_TAGS or the drill image name appears anywhere it could ship:

  - any Dockerfile default (`ARG GO_TAGS` must be empty; only the sanctioned `go build -tags "${GO_TAGS}"` line)
  - any workflow other than machine-keycloak-e2e.yml (release.yml, build-multiarch.yml, ...)
  - the Makefile, docker-compose.yml, charts/, scripts/ (non-test), image/, anything else outside the allowlist
  - the drill workflow itself, except the single sanctioned `docker build --build-arg GO_TAGS=... -t $LDAPIUM_UI_DRILL_IMAGE ui`
    line, and it must never push, tag or log in.

Usage:  test-machine-write-drill-guard.py [--root DIR]     scan DIR (default: the repository)
        test-machine-write-drill-guard.py --self-test      mutation test: copies the repository files that
                                                           matter into a temp tree, applies each mutation and
                                                           requires the scan to FAIL (and the clean tree to pass)
"""
import argparse
import os
import pathlib
import re
import shutil
import sys
import tempfile

TAG = 'machinewritedrill'
IMAGE = 'machine-drill'
REPO = pathlib.Path(__file__).resolve().parents[2]
SKIP_DIRS = {'.git', 'node_modules', '.claude', '.omc', 'dist', '__pycache__', '.venv'}

# Files that may mention the tag in any way (code that defines it, its tests, this guard, prose).
ALLOW_ANY = {
  'ui/backend/internal/httpapi/machine_write_drill.go',
  'ui/backend/internal/config/machine_write_drill.go',
  'ui/backend/internal/httpapi/machine_write_closed_test.go',
  'scripts/test/test-machine-write-drill-guard.py',
}
# Files that may mention the tag / GO_TAGS (they build or run the drill image) but are still scanned for anything
# that publishes, saves or uploads an image.
ALLOW_CHECKED = {
  'scripts/test/test-machine-write-drill.py',
  'scripts/test/test-machine-write-drill-artifact.sh',
}
DOCKERFILE = 'ui/Dockerfile'
DRILL_WORKFLOW = '.github/workflows/machine-keycloak-e2e.yml'
SANCTIONED_BUILD = re.compile(
  r'^\s*run:\s*docker build --build-arg GO_TAGS=' + TAG + r' -t "\$LDAPIUM_UI_DRILL_IMAGE" ui\s*$')
SANCTIONED_GO = 'RUN CGO_ENABLED=0 GOOS=linux go build -tags "${GO_TAGS}" -trimpath -ldflags="-s -w" -o /out/server ./cmd/server'
FORBIDDEN_IN_DRILL_WORKFLOW = re.compile(
  r'docker push|docker tag|docker login|docker/login-action|docker/build-push-action|ghcr\.io|--push\b|type=registry'
  r'|docker (image )?save|docker export|upload-artifact|skopeo|\bcrane\b')
# `go build/install/run` with -tags, or GOFLAGS carrying -tags, outside the one sanctioned Dockerfile line.
TAGGED_GO_BUILD = re.compile(r'go\s+(build|install|run)\b.*-tags|GOFLAGS.*-tags')
NEEDLES = (TAG, IMAGE)


def is_comment(rel, line):
  if rel.endswith('.go'):
    return False  # a Go build constraint IS a comment, so no Go line is ever skipped
  return line.lstrip().startswith('#')


def text_files(root):
  for base, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for name in files:
      path = pathlib.Path(base) / name
      try:
        yield path.relative_to(root).as_posix(), path.read_text(encoding='utf-8')
      except (UnicodeDecodeError, OSError):
        continue


def scan(root):
  problems = []
  seen = {'config_go': False, 'dockerfile_arg': False, 'drill_build': False, 'drill_go': False, 'closed_test': False}
  for rel, text in text_files(root):
    lines = text.splitlines()
    if rel in ALLOW_CHECKED:
      for n, line in enumerate(lines, 1):
        if not is_comment(rel, line) and FORBIDDEN_IN_DRILL_WORKFLOW.search(line):
          problems.append(f'{rel}:{n}: a drill script must not push, save, tag or upload an image: {line.strip()}')
      continue
    if rel.endswith('.md') or rel in ALLOW_ANY:
      if rel == 'ui/backend/internal/httpapi/machine_write_drill.go':
        seen['drill_go'] = bool(lines) and lines[0] == '//go:build ' + TAG
      if rel == 'ui/backend/internal/config/machine_write_drill.go':
        seen['config_go'] = bool(lines) and lines[0] == '//go:build ' + TAG
      if rel == 'ui/backend/internal/httpapi/machine_write_closed_test.go':
        seen['closed_test'] = bool(lines) and lines[0] == '//go:build !' + TAG
      continue
    for n, line in enumerate(lines, 1):
      commented = is_comment(rel, line)
      if rel == DOCKERFILE:
        if 'GO_TAGS' in line and not commented:
          if line.strip() == 'ARG GO_TAGS=""':
            seen['dockerfile_arg'] = True
          elif line.strip() != SANCTIONED_GO:
            problems.append(f'{rel}:{n}: GO_TAGS may only be `ARG GO_TAGS=""` and the sanctioned go build line: {line.strip()}')
        if not commented and any(x in line for x in NEEDLES):
          problems.append(f'{rel}:{n}: the drill tag/image appears in an executable Dockerfile line: {line.strip()}')
        if not commented and TAGGED_GO_BUILD.search(line) and line.strip() != SANCTIONED_GO:
          problems.append(f'{rel}:{n}: a tagged go build is only allowed on the sanctioned line: {line.strip()}')
        continue
      if rel == DRILL_WORKFLOW:
        if commented:
          continue
        if TAG in line or 'GO_TAGS' in line:
          if SANCTIONED_BUILD.match(line):
            seen['drill_build'] = True
          else:
            problems.append(f'{rel}:{n}: only the sanctioned drill `docker build` line may use the tag/GO_TAGS: {line.strip()}')
        if FORBIDDEN_IN_DRILL_WORKFLOW.search(line):
          problems.append(f'{rel}:{n}: the drill workflow must not push, save, tag, upload or log in: {line.strip()}')
        if TAGGED_GO_BUILD.search(line):
          problems.append(f'{rel}:{n}: a tagged go build is not allowed in the drill workflow: {line.strip()}')
        continue
      if commented:
        continue
      if TAGGED_GO_BUILD.search(line):
        problems.append(f'{rel}:{n}: go build/install/run with -tags (or GOFLAGS -tags) is forbidden outside the sanctioned Dockerfile line: {line.strip()}')
      if any(x in line for x in NEEDLES) or re.search(r'GO_TAGS\s*[=:]\s*\S', line):
        problems.append(f'{rel}:{n}: the drill tag/image/GO_TAGS must not appear outside the drill files: {line.strip()}')
  root = pathlib.Path(root)
  if not seen['dockerfile_arg'] and (root / DOCKERFILE).exists():
    problems.append(f'{DOCKERFILE}: `ARG GO_TAGS=""` (empty default) is missing')
  if not seen['drill_go'] and (root / 'ui/backend/internal/httpapi/machine_write_drill.go').exists():
    problems.append('machine_write_drill.go must start with `//go:build ' + TAG + '`')
  if not seen['config_go'] and (root / 'ui/backend/internal/config/machine_write_drill.go').exists():
    problems.append('config/machine_write_drill.go must start with `//go:build ' + TAG + '`')
  if not seen['closed_test']:
    problems.append('machine_write_closed_test.go must exist and start with `//go:build !' + TAG + '`')
  if (root / DRILL_WORKFLOW).exists() and not seen['drill_build']:
    problems.append(f'{DRILL_WORKFLOW}: the sanctioned drill image build line is missing')
  return problems


def self_test():
  keep = ('Dockerfile', 'Makefile', '.yml', '.yaml', '.go', '.sh', '.py', '.md', '.json', '.toml', '.tpl', '.txt')
  tmp = pathlib.Path(tempfile.mkdtemp(prefix='drill-guard-'))
  try:
    clean = tmp / 'clean'
    for rel, text in text_files(REPO):
      if rel.endswith(keep) or pathlib.PurePosixPath(rel).name in ('Dockerfile', 'Makefile'):
        dest = clean / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text, encoding='utf-8')
    base = scan(clean)
    if base:
      print('self-test: the clean tree must pass but has problems:\n  ' + '\n  '.join(base), file=sys.stderr)
      return 1
    print('PASS: clean tree: 0 problems', flush=True)

    def edit(rel, fn):
      def go(root):
        p = root / rel
        p.write_text(fn(p.read_text(encoding='utf-8')), encoding='utf-8')
      return go

    def append(rel, extra):
      return edit(rel, lambda t: t + extra)

    def new(rel, content):
      def go(root):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding='utf-8')
      return go

    mutations = {
      'Dockerfile default ARG GO_TAGS=tag': edit(DOCKERFILE, lambda t: t.replace('ARG GO_TAGS=""', 'ARG GO_TAGS=' + TAG)),
      'Dockerfile ENV GO_TAGS': append(DOCKERFILE, '\nENV GO_TAGS=' + TAG + '\n'),
      'Dockerfile hard-coded -tags': edit(DOCKERFILE, lambda t: t.replace('-tags "${GO_TAGS}"', '-tags ' + TAG)),
      'Dockerfile empty ARG removed': edit(DOCKERFILE, lambda t: t.replace('ARG GO_TAGS=""\n', '')),
      'release.yml builds the tag': append('.github/workflows/release.yml', '\n      - run: docker build --build-arg GO_TAGS=' + TAG + ' -t x ui\n'),
      'build-multiarch.yml sets GO_TAGS': append('.github/workflows/build-multiarch.yml', '\n  GO_TAGS: ' + TAG + '\n'),
      'release.yml publishes the drill image': append('.github/workflows/release.yml', '\n      - run: docker push ldapium-ui:' + IMAGE + '\n'),
      'Makefile target uses the tag': append('Makefile', '\nrelease-ui:\n\tcd ui/backend && go build -tags ' + TAG + ' ./cmd/server\n'),
      'Makefile build-arg': append('Makefile', '\nui-image:\n\tdocker build --build-arg GO_TAGS=' + TAG + ' ui\n'),
      'Helm chart default image tag': new('charts/ldapium/values-drill.yaml', 'ui:\n  image:\n    tag: ' + IMAGE + '\n'),
      'docker-compose default': new('docker-compose.override.yml', 'services:\n  ui:\n    build:\n      args:\n        GO_TAGS: ' + TAG + '\n'),
      'script default': new('scripts/offline-bundle-drill.sh', '#!/bin/sh\ndocker build --build-arg GO_TAGS=' + TAG + ' ui\n'),
      'drill workflow pushes the drill image': append(DRILL_WORKFLOW, '\n      - run: docker push "$LDAPIUM_UI_DRILL_IMAGE"\n'),
      'drill workflow uses the tag outside the sanctioned line': append(DRILL_WORKFLOW, '\n      - run: docker build --build-arg GO_TAGS=' + TAG + ' -t other ui\n'),
      'drill workflow loses its sanctioned build line': edit(DRILL_WORKFLOW, lambda t: re.sub(r'(?m)^.*GO_TAGS=' + TAG + '.*$', '', t)),
      **{f'drill workflow uses {tok}': append(DRILL_WORKFLOW, f'\n      - run: echo {tok} x\n')
         for tok in ('--push', 'type=registry', 'docker save', 'upload-artifact', 'skopeo', 'crane', 'docker image save')},
      'drill workflow does a tagged go build': append(DRILL_WORKFLOW, '\n      - run: go build -tags netgo ./...\n'),
      'drill script pushes an image': append('scripts/test/test-machine-write-drill.py', '\n# x\nsubprocess_cmd = "docker push ldapium-ui:machine-drill"\n'),
      'drill script saves an image': append('scripts/test/test-machine-write-drill.py', '\nx = "docker save ldapium-ui:x"\n'),
      'artifact script saves an image': append('scripts/test/test-machine-write-drill-artifact.sh', '\ndocker save x\n'),
      'Dockerfile other tagged go build': append(DOCKERFILE, '\nRUN go build -tags netgo -o /x ./cmd/server\n'),
      'sanctioned go line with a suffix': edit(DOCKERFILE, lambda t: t.replace('./cmd/server\n', './cmd/server && echo x\n', 1)),
      'Makefile tagged go build': append('Makefile', '\nx:\n\tgo build -tags netgo ./...\n'),
      'workflow GOFLAGS tags': append('.github/workflows/ci.yml', '\n  GOFLAGS: -tags=netgo\n'),
      'script go install with tags': new('scripts/x-install.sh', '#!/bin/sh\ngo install -tags netgo ./...\n'),
      'ci.yml builds the drill tag itself': append('.github/workflows/ci.yml', '\n      - run: go build -tags ' + TAG + ' ./...\n'),
      'drill build constraint removed': edit('ui/backend/internal/httpapi/machine_write_drill.go', lambda t: t.replace('//go:build ' + TAG, '', 1)),
      'config drill build constraint removed': edit('ui/backend/internal/config/machine_write_drill.go', lambda t: t.replace('//go:build ' + TAG, '', 1)),
      'closed test constraint removed': edit('ui/backend/internal/httpapi/machine_write_closed_test.go', lambda t: t.replace('//go:build !' + TAG, '', 1)),
      'Go file elsewhere uses the tag': new('ui/backend/internal/config/x.go', '//go:build ' + TAG + '\n\npackage config\n'),
    }
    failed = 0
    for name, mutate in mutations.items():
      work = tmp / ('m-' + str(abs(hash(name))))
      shutil.copytree(clean, work)
      mutate(work)
      problems = scan(work)
      if problems:
        print(f'PASS: mutation "{name}" is detected ({len(problems)} problem(s); first: {problems[0][:110]})', flush=True)
      else:
        failed += 1
        print(f'FAIL: mutation "{name}" was NOT detected', file=sys.stderr, flush=True)
      shutil.rmtree(work)
    print(f'self-test: {len(mutations) - failed}/{len(mutations)} mutations detected', flush=True)
    return 1 if failed else 0
  finally:
    shutil.rmtree(tmp, ignore_errors=True)


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument('--root', default=str(REPO))
  ap.add_argument('--self-test', action='store_true')
  args = ap.parse_args()
  if args.self_test:
    return self_test()
  problems = scan(pathlib.Path(args.root))
  if problems:
    print('drill guard FAILED:\n  ' + '\n  '.join(problems), file=sys.stderr)
    return 1
  print('drill guard: OK (the drill tag is confined to the drill files)')
  return 0


if __name__ == '__main__':
  sys.exit(main())
