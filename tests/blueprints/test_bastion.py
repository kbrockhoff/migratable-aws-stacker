from stacker.context import Context
from stacker.blueprints.testutil import BlueprintTestCase
from blueprints.bastion import Bastion

class TestBastionBlueprint(BlueprintTestCase):
    def setUp(self):
        self.ctx = Context({
            'namespace': 'test',
            'environment': 'test',
            'region': 'us-east-1'
        })
        self.blueprint = Bastion('test_bastion', self.ctx)
        # Set required variables for testing
        self.blueprint.variables = {
            'VpcId': 'vpc-0b84ca1931e15a680',
            'Environment': 'test',
            'NamePrefix': 'unit-tests',
            'Tags': {
                'ck-costcenter': '1234567890',
                'ck-confidentiality': 'high',
                'ck-project': 'test',
                'ck-dataowners': 'test',
                'ck-codeowners': 'test',
                'ck-privacyreview': 'test',
                'ck-securityreview': 'test',
                'ck-projectowners': 'test',
                'ck-dataregulations': 'test',
                'ck-availability': 'preemptible',
                'ck-deployer': 'Stacker',
                'ck-deletiondate': 'never'
            }
        }

    def test_bastion(self):
        self.blueprint.create_template()
        self.assertRenderedBlueprint(self.blueprint)
