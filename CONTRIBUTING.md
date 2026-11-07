# Contributing

## Branches

- `main` holds what has passed every test.
- `develop` collects finished work.
- Work happens on a branch of its own, which goes into `develop` through a pull request.

Nobody pushes to `main` or `develop` directly. In an emergency, for example when
GitHub Actions is down, an admin can override this.

## Checks

| When | Workflow | What runs |
| --- | --- | --- |
| Every pull request, every push to `main` and `develop` | `ci.yml` | Unit tests, types, desktop apps, end-to-end tests, passkeys, Authentik and packages |
| Pull requests to `main`, or by hand | `vm.yml` | All tests in virtual machines, one job each |

Branch protection looks at the summary jobs `ci-ok` and `vm-ok`, so a new suite needs
no change there. The list of suites comes from `test/regression.py`.

To run a VM test on any branch, start `VM tests` under Actions.

## Before a pull request

```bash
make regression-fast
```

`make regression` adds the virtual machines. It needs KVM and Podman, and downloads
several GB. A single suite runs with `python3 test/regression.py vm-power`, and
`python3 test/regression.py --list` shows all of them.

## Workflows on a public repository

Anyone can open a pull request here, so workflows run untrusted code:

- They only get `contents: read`, and use no secrets.
- Never use `pull_request_target`, and never add a self-hosted runner.
- Pin actions to a commit, and set `timeout-minutes` on every job.

## Style

Code, comments and documentation are in English. The project is under the
[AGPL-3.0](LICENSE), and so are contributions.
