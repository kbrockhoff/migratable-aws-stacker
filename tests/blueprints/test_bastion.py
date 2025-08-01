import unittest
from unittest.mock import patch, MagicMock
from stacker.context import Context
from stacker.blueprints.testutil import BlueprintTestCase
from stacker.blueprints.variables.types import EC2VPCId
from blueprints.bastion import Bastion

class TestBastionBlueprint(BlueprintTestCase):
    def setUp(self):
        self.ctx = Context({
            'namespace': 'test',
            'environment': 'test',
            'region': 'us-east-1'
        })
        self.blueprint = Bastion('test_bastion', self.ctx)

    def test_bastion_blueprint_creation(self):
        """Test that the bastion blueprint can be created with required variables."""
        # Test that blueprint has the expected VARIABLES defined
        self.assertIn('VpcId', self.blueprint.VARIABLES)
        self.assertIn('Environment', self.blueprint.VARIABLES)
        self.assertIn('NamePrefix', self.blueprint.VARIABLES)
        self.assertIn('Tags', self.blueprint.VARIABLES)
        
        # Test variable types
        self.assertEqual(self.blueprint.VARIABLES['VpcId']['type'], EC2VPCId)
        self.assertEqual(self.blueprint.VARIABLES['Environment']['type'], str)
        self.assertEqual(self.blueprint.VARIABLES['NamePrefix']['type'], str)

    def test_bastion_ami_mapping(self):
        """Test that AMI mapping is created correctly."""
        # Create the AMI mapping
        self.blueprint.create_ami_mapping()
        
        # Verify that mappings are created
        mappings = self.blueprint.template.mappings
        self.assertIn('AmiMap', mappings)
        
        # Verify some regions are included
        ami_map = mappings['AmiMap']
        self.assertIn('us-east-1', ami_map)
        self.assertIn('us-west-2', ami_map)
        
        # Verify bastion AMI is mapped
        self.assertIn('bastion', ami_map['us-east-1'])

    def test_bastion_user_data_generation(self):
        """Test user data generation."""
        user_data = self.blueprint.generate_user_data()
        
        # Verify user data is base64 encoded
        self.assertIsInstance(user_data, str)
        self.assertTrue(len(user_data) > 0)
        
        # Decode and verify content
        import base64
        decoded = base64.b64decode(user_data).decode()
        
        # Verify key components are in user data
        self.assertIn('#!/usr/bin/env bash', decoded)
        self.assertIn('StrictHostKeyChecking no', decoded)
        self.assertIn('amazon-ssm-agent', decoded)
