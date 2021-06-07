#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from '@aws-cdk/core';
import { CloudhsmBaseStack } from '../lib/cloudhsm-base-stack';

const app = new cdk.App();
new CloudhsmBaseStack(app, 'CloudhsmBaseStack');
