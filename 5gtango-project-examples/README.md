# 5GTANGO Example Projects

This folder contains example 5GTANGO SDK projects.

## Packaging

Use tng-sdk-package to packge the projects:

```
tng-pkg -p <project-folder>
```

### Examples

```sh
# command
tng-pkg -p minimal-ns/ ../5gtango-package-examples/

# output
===============================================================================
P A C K A G I N G   R E P O R T
===============================================================================
Packaged:    minimal-ns/
Project:     eu.5gtango.generated-project.0.1
Artifacts:   3
Output:      ../5gtango-package-examples/eu.5gtango.generated-project.0.1.tgo
Error:       None
Result:      Success.
===============================================================================
```

```sh
# command
tng-pkg -p smoke-test-ns/ -o ../5gtango-package-examples/

# output
===============================================================================
P A C K A G I N G   R E P O R T
===============================================================================
Packaged:    smoke-test-ns/
Project:     eu.5gtango.smoke-test-ns.0.1
Artifacts:   3
Output:      ../5gtango-package-examples/eu.5gtango.smoke-test-ns.0.1.tgo
Error:       None
Result:      Success.
===============================================================================
```
