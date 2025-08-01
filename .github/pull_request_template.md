# Pull Request

## Description
<!-- Provide a brief description of the infrastructure changes in this PR -->

## Type of Change
<!-- Check all that apply -->
- [ ] Bug fix (fixes an issue with existing infrastructure)
- [ ] New infrastructure component (adds new AWS resources or blueprints)
- [ ] Breaking change (infrastructure change that would affect existing deployments)
- [ ] Configuration update (changes to stacker configs or variables)
- [ ] Documentation update
- [ ] Refactoring (restructures code without changing infrastructure behavior)
- [ ] Security improvement
- [ ] Cost optimization
- [ ] Blueprint improvements

## Infrastructure Changes Made
<!-- List the specific infrastructure changes made in this PR -->
- 
- 
- 

## Testing
<!-- Describe the tests you ran to verify your changes -->
- [ ] I have run `uv run python -m pytest tests/` locally
- [ ] I have added/updated unit tests for blueprints
- [ ] I have tested stack deployment in a development environment
- [ ] All tests pass
- [ ] I have validated CloudFormation templates are syntactically correct
- [ ] I have verified resource tagging is consistent

## AWS Resources
<!-- List AWS resources that will be created, modified, or deleted -->
### Created:
- 

### Modified:
- 

### Deleted:
- 

## Documentation
- [ ] I have updated the README.md if needed
- [ ] I have added/updated Python docstrings
- [ ] I have updated infrastructure documentation
- [ ] I have documented any new configuration variables

## Breaking Changes
<!-- If this is a breaking change, describe what users need to do to migrate -->
- [ ] This is not a breaking change
- [ ] This is a breaking change (describe migration path below)

<!-- Migration instructions for breaking changes -->

## Security Considerations
- [ ] I have reviewed security implications of these infrastructure changes
- [ ] Resource permissions follow the principle of least privilege
- [ ] Sensitive data is properly encrypted (at rest and in transit)
- [ ] Network security groups are appropriately configured
- [ ] IAM roles and policies have been reviewed for security best practices

## Cost Impact
- [ ] I have considered the cost implications of these changes
- [ ] New resources are appropriately sized for their intended use
- [ ] I have verified resource cleanup/termination procedures

## Checklist
- [ ] My code follows the project's Python style guidelines
- [ ] I have performed a self-review of my infrastructure code
- [ ] I have added appropriate comments and docstrings
- [ ] My changes generate no new linting warnings
- [ ] I have added tests that validate my blueprint functionality
- [ ] New and existing unit tests pass locally with my changes
- [ ] I have verified CloudFormation template syntax is valid
- [ ] Resource tags follow the project's tagging strategy

## Additional Notes
<!-- Add any additional notes, deployment instructions, or context about the PR -->