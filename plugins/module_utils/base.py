# Copyright (c) 2020 Jiří Altman <jiri.altman@konicaminolta.cz>
# Copyright (c) 2005-2013 Canonical Limited.  All rights reserved.
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT


"""Base module for Landscape API (Python 3)."""

__all__ = ["run_query", "API", "errors"]

from ansible.module_utils.json_utils import json
import argparse
import copy
import hmac
import inspect
# import json
import os
import re
import sys
import textwrap
import time
import types
from base64 import b64encode
from collections import namedtuple
from datetime import date, datetime
from functools import partial
from hashlib import sha256
from io import StringIO
from pprint import pprint
from urllib.parse import quote, urlparse, urlunparse



import requests

LATEST_VERSION = "2011-08-01"
FUTURE_VERSION = "2013-11-04"


# The list of API actions that require a raw output (they will use vanilla
# "print" instead of pprint). This is useful for actions that return files, so
# that you can pipe the output to a file.
RAW_ACTIONS_LIST = ("get-script-code",)

SCHEMA = {
    "AcceptPendingComputers": {
        "2011-08-01": {
            "doc": "\n    Accept a list of pending computers associated with the account used for\n    authentication.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InsufficientLicenses"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "AcceptPendingComputers",
            "parameters": [
                {
                    "doc": "A list of computer IDs to accept.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": {},
                    "doc": "A mapping from pending computer IDs to existing ones.",
                    "key": {
                        "doc": "The ID of the pending computer.",
                        "type": "integer"
                    },
                    "name": "existing_ids",
                    "optional": True,
                    "type": "mapping",
                    "value": {
                        "doc": "The ID of the computer to replace.",
                        "type": "integer"
                    }
                },
                {
                    "default": None,
                    "doc": "The access group to put the computers into",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Accept a list of pending computers associated with the account used for\n    authentication.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InsufficientLicenses"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "AcceptPendingComputers",
            "parameters": [
                {
                    "doc": "A list of computer IDs to accept.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": {},
                    "doc": "A mapping from pending computer IDs to existing ones.",
                    "key": {
                        "doc": "The ID of the pending computer.",
                        "type": "integer"
                    },
                    "name": "existing_ids",
                    "optional": True,
                    "type": "mapping",
                    "value": {
                        "doc": "The ID of the computer to replace.",
                        "type": "integer"
                    }
                },
                {
                    "default": None,
                    "doc": "The access group to put the computers into",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "AddAPTSourcesToRepositoryProfile": {
        "2011-08-01": {
            "doc": "Add APT sources to a repository profile.\n            An activity will be created to add the given source to the the\n            computers associated with the given profile.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "AddAPTSourcesToRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the APT sources to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "apt_sources",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add APT sources to a repository profile.\n            An activity will be created to add the given source to the the\n            computers associated with the given profile.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "AddAPTSourcesToRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the APT sources to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "apt_sources",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddAccessGroupsToRole": {
        "2011-08-01": {
            "doc": "Add the given access groups to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownAccessGroups"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "AddAccessGroupsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of access groups to add to the role.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "access_groups",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add the given access groups to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownAccessGroups"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "AddAccessGroupsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of access groups to add to the role.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "access_groups",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddAnnotationToComputers": {
        "2011-08-01": {
            "doc": "\n    Add annotation key and optional value to a selection of computers.",
            "errors": [
                {
                    "code": "InvalidAnnotationKey"
                },
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "AddAnnotationToComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to which to add the annotation.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Annotation key to add to the selected computers.",
                    "name": "key",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Annotation value associated with the provided key to add to the selected computers.",
                    "name": "value",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Add annotation key and optional value to a selection of computers.",
            "errors": [
                {
                    "code": "InvalidAnnotationKey"
                },
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "AddAnnotationToComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to which to add the annotation.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Annotation key to add to the selected computers.",
                    "name": "key",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Annotation value associated with the provided key to add to the selected computers.",
                    "name": "value",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "AddPackageFiltersToPocket": {
        "2011-08-01": {
            "doc": "\n    Add package filters to a repository pocket.  The pocket must be in pull\n    mode and support blacklist/whitelist filtering.\n    ",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "NoPocketFiltering"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "AddPackageFiltersToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to operate on.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be added or removed from the pocket filter.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Add package filters to a repository pocket.  The pocket must be in pull\n    mode and support blacklist/whitelist filtering.\n    ",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "NoPocketFiltering"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "AddPackageFiltersToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to operate on.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be added or removed from the pocket filter.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddPermissionsToRole": {
        "2011-08-01": {
            "doc": "Add permissions to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                },
                {
                    "code": "InvalidRolePermissions"
                }
            ],
            "name": "AddPermissionsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of permissions to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "permissions",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add permissions to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                },
                {
                    "code": "InvalidRolePermissions"
                }
            ],
            "name": "AddPermissionsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of permissions to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "permissions",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddPersonsToRole": {
        "2011-08-01": {
            "doc": "Add permissions to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownPersonEmails"
                }
            ],
            "name": "AddPersonsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of emails of persons to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "persons",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add permissions to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownPersonEmails"
                }
            ],
            "name": "AddPersonsToRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of emails of persons to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "persons",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddPocketsToRepositoryProfile": {
        "2011-08-01": {
            "doc": "Add repository pockets to a repository profile.\n            An activity will be created to add the given pockets to the APT\n            sources of the computers associated with the given profile. ",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "AddPocketsToRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the pockets to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "type": "list"
                },
                {
                    "doc": "The name of the series the pockets belongs to.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add repository pockets to a repository profile.\n            An activity will be created to add the given pockets to the APT\n            sources of the computers associated with the given profile. ",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "AddPocketsToRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the pockets to add.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "type": "list"
                },
                {
                    "doc": "The name of the series the pockets belongs to.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "AddTagsToComputers": {
        "2011-08-01": {
            "doc": "Add tags to a selection of computers.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTag"
                }
            ],
            "name": "AddTagsToComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to add tags to.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Tag names to be applied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add tags to a selection of computers.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTag"
                }
            ],
            "name": "AddTagsToComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to add tags to.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Tag names to be applied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "AddUploaderGPGKeysToPocket": {
        "2011-08-01": {
            "doc": "\n    Add GPG keys to a repository pocket in upload mode to validate uploaded\n    packages.\n    ",
            "errors": [
                {
                    "code": "GPGKeyNotAssociated"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "GPGKeyAlreadyAssociated"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "AddUploaderGPGKeysToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket on which to associate keys.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of GPG keys on which to operate.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "gpg_keys",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Add GPG keys to a repository pocket in upload mode to validate uploaded\n    packages.\n    ",
            "errors": [
                {
                    "code": "GPGKeyNotAssociated"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "GPGKeyAlreadyAssociated"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "AddUploaderGPGKeysToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket on which to associate keys.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of GPG keys on which to operate.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "gpg_keys",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "ApproveActivities": {
        "2011-08-01": {
            "doc": "Approve activities associated with the current account.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidActivityStatusChange"
                }
            ],
            "name": "ApproveActivities",
            "parameters": [
                {
                    "doc": "A query string used to select activities on which to operate.",
                    "name": "query",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Approve activities associated with the current account.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidActivityStatusChange"
                }
            ],
            "name": "ApproveActivities",
            "parameters": [
                {
                    "doc": "A query string used to select activities on which to operate.",
                    "name": "query",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "AssociateAlert": {
        "2011-08-01": {
            "doc": "\n    Associate an alert to computers with specific tags or to all computers.\n    If a tag with a given name doesn't exist, it will be automatically\n    created. An 'all_computers' value of 'true' and a list of tags are mutually\n    exclusive. Only one or the other may be passed.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "InvalidAlertTypeError"
                }
            ],
            "name": "AssociateAlert",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Associate an alert to computers with specific tags or to all computers.\n    If a tag with a given name doesn't exist, it will be automatically\n    created. An 'all_computers' value of 'true' and a list of tags are mutually\n    exclusive. Only one or the other may be passed.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "InvalidAlertTypeError"
                }
            ],
            "name": "AssociateAlert",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "AssociatePackageProfile": {
        "2011-08-01": {
            "doc": "\n    Associate a package profile to computers with specific tags or to all\n    computers. If a tag with a given name doesn't exist, it will be\n    automatically created.\n\n    An 'all_computers' value of 'true' and a list of tags are mutually\n    exclusive. Only one or the other may be passed.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "AssociatePackageProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Associate a package profile to computers with specific tags or to all\n    computers. If a tag with a given name doesn't exist, it will be\n    automatically created.\n\n    An 'all_computers' value of 'true' and a list of tags are mutually\n    exclusive. Only one or the other may be passed.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "AssociatePackageProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "AssociateRemovalProfile": {
        "2011-08-01": {
            "doc": "\n    Associate a removal profile to computers with the specified tags,\n    or all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "AssociateRemovalProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Associate a removal profile to computers with the specified tags,\n    or all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "AssociateRemovalProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "AssociateRepositoryProfile": {
        "2011-08-01": {
            "doc": "Associate repository profile to computers with specified tags\n            or to all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRepositoryProfile"
                }
            ],
            "name": "AssociateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Associate repository profile to computers with specified tags\n            or to all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRepositoryProfile"
                }
            ],
            "name": "AssociateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "AssociateUpgradeProfile": {
        "2011-08-01": {
            "doc": "\n    Associate an upgrade profile to computers with the specified tags,\n    or all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "AssociateUpgradeProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Associate an upgrade profile to computers with the specified tags,\n    or all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "AssociateUpgradeProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "CancelActivities": {
        "2011-08-01": {
            "doc": "\n    Cancel activities associated with the current account.\n\n    Returns a list of activities ids that were cancelled.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidActivityStatusChange"
                }
            ],
            "name": "CancelActivities",
            "parameters": [
                {
                    "doc": "A query string used to select activities on which to operate.",
                    "name": "query",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Cancel activities associated with the current account.\n\n    Returns a list of activities ids that were cancelled.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidActivityStatusChange"
                }
            ],
            "name": "CancelActivities",
            "parameters": [
                {
                    "doc": "A query string used to select activities on which to operate.",
                    "name": "query",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "ChangeComputersAccessGroup": {
        "2011-08-01": {
            "doc": "Change the access group for a selection of computers.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "ChangeComputersAccessGroup",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to change access group for.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the access group to assign selected computers to.",
                    "name": "access_group",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Change the access group for a selection of computers.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "ChangeComputersAccessGroup",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to change access group for.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the access group to assign selected computers to.",
                    "name": "access_group",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CopyPackageProfile": {
        "2011-08-01": {
            "doc": "\n    Copy an existing package profile to a package profile with a new name and\n    optionally a different title and description.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicatePackageProfile"
                }
            ],
            "name": "CopyPackageProfile",
            "parameters": [
                {
                    "doc": "A name of the existing package profile to copy.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The profile name of the copied package profile.",
                    "name": "destination_name",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A title for the new profile. If not specified, the title of the source profile is used.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A description for the new profile. If not specified, the title of the source profile is used.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Name of the access group to copy the profile to. Defaults to the origin's access group.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Copy an existing package profile to a package profile with a new name and\n    optionally a different title and description.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicatePackageProfile"
                }
            ],
            "name": "CopyPackageProfile",
            "parameters": [
                {
                    "doc": "A name of the existing package profile to copy.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The profile name of the copied package profile.",
                    "name": "destination_name",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A title for the new profile. If not specified, the title of the source profile is used.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A description for the new profile. If not specified, the title of the source profile is used.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Name of the access group to copy the profile to. Defaults to the origin's access group.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CopyRole": {
        "2011-08-01": {
            "doc": "Copy an existing access role to a role with a new name.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "InvalidRoleName"
                },
                {
                    "code": "DuplicateRoleName"
                }
            ],
            "name": "CopyRole",
            "parameters": [
                {
                    "doc": "The name of the existing role.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the new role.",
                    "name": "destination_name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The description of the new role.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Copy an existing access role to a role with a new name.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "InvalidRoleName"
                },
                {
                    "code": "DuplicateRoleName"
                }
            ],
            "name": "CopyRole",
            "parameters": [
                {
                    "doc": "The name of the existing role.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the new role.",
                    "name": "destination_name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The description of the new role.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CopyScript": {
        "2011-08-01": {
            "doc": "Copy an existing script to a script with a new name.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "CopyScript",
            "parameters": [
                {
                    "doc": "The identity of the existing script.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The title of the new script.",
                    "name": "destination_title",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The access group for the new script. It defaults to the same access group as the existing script.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Copy an existing script to a script with a new name.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "CopyScript",
            "parameters": [
                {
                    "doc": "The identity of the existing script.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The title of the new script.",
                    "name": "destination_title",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The access group for the new script. It defaults to the same access group as the existing script.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateAPTSource": {
        "2011-08-01": {
            "doc": "\n    Create an APT source in the account used for authentication.\n    ",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateAPTSource"
                },
                {
                    "code": "InvalidAPTLine"
                }
            ],
            "name": "CreateAPTSource",
            "parameters": [
                {
                    "doc": "Name of the APT source. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The APT line of the source.",
                    "name": "apt_line",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Name of the GPG key used to sign the repository",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the APT source into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Create an APT source in the account used for authentication.\n    ",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateAPTSource"
                },
                {
                    "code": "InvalidAPTLine"
                }
            ],
            "name": "CreateAPTSource",
            "parameters": [
                {
                    "doc": "Name of the APT source. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The APT line of the source.",
                    "name": "apt_line",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Name of the GPG key used to sign the repository",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the APT source into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateAccessGroup": {
        "2011-08-01": {
            "doc": "Create a new access group.",
            "errors": [
                {
                    "code": "DuplicateAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAccessGroup"
                }
            ],
            "name": "CreateAccessGroup",
            "parameters": [
                {
                    "doc": "The title of the access group.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "The title of the parent access group.",
                    "name": "parent",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a new access group.",
            "errors": [
                {
                    "code": "DuplicateAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAccessGroup"
                }
            ],
            "name": "CreateAccessGroup",
            "parameters": [
                {
                    "doc": "The name of the access group.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Description of the access group.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name or ID of the parent access group.",
                    "name": "parent",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateCloudOtps": {
        "2011-08-01": {
            "doc": "\n    Create one-time passwords used for registration of cloud instances.\n    ",
            "errors": [],
            "name": "CreateCloudOtps",
            "parameters": [
                {
                    "default": 1,
                    "doc": "The number of OTPs to create",
                    "name": "count",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Create one-time passwords used for registration of cloud instances.\n    ",
            "errors": [],
            "name": "CreateCloudOtps",
            "parameters": [
                {
                    "default": 1,
                    "doc": "The number of OTPs to create",
                    "name": "count",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "CreateDistribution": {
        "2011-08-01": {
            "doc": "\n    Create a repository distribution associated with the account.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateDistribution"
                }
            ],
            "name": "CreateDistribution",
            "parameters": [
                {
                    "doc": "The name of the distribution. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the distribution into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Create a repository distribution associated with the account.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateDistribution"
                }
            ],
            "name": "CreateDistribution",
            "parameters": [
                {
                    "doc": "The name of the distribution. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the distribution into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreatePackageProfile": {
        "2011-08-01": {
            "doc": "\n    Create a package profile.\n\n    source_computer_id and material are mutually exclusive.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidPackageProfileName"
                },
                {
                    "code": "InvalidPackageProfileMaterial"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "DuplicatePackageProfile"
                },
                {
                    "code": "NoFoundPackages"
                },
                {
                    "code": "InvalidConstraintType"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "CreatePackageProfile",
            "parameters": [
                {
                    "doc": "The title of the package profile to create.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The description of the new profile.",
                    "name": "description",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A computer ID to find a computer which will be used as the basis of the package profile.",
                    "name": "source_computer_id",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "Package data in the format of 'dpkg --get-selections' or CSV (as exported by Landscape).",
                    "name": "material",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Alternative to material, constraint specifications in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": "global",
                    "doc": "Optional name of the access group to create the profile into",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Create a package profile.\n\n    source_computer_id and material are mutually exclusive.\n    ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidPackageProfileName"
                },
                {
                    "code": "InvalidPackageProfileMaterial"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "DuplicatePackageProfile"
                },
                {
                    "code": "NoFoundPackages"
                },
                {
                    "code": "InvalidConstraintType"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "CreatePackageProfile",
            "parameters": [
                {
                    "doc": "The title of the package profile to create.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The description of the new profile.",
                    "name": "description",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A computer ID to find a computer which will be used as the basis of the package profile.",
                    "name": "source_computer_id",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "Package data in the format of 'dpkg --get-selections' or CSV (as exported by Landscape).",
                    "name": "material",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Alternative to material, constraint specifications in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": "global",
                    "doc": "Optional name of the access group to create the profile into",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreatePocket": {
        "2011-08-01": {
            "doc": "Create a pocket associated with a series in the account.",
            "errors": [
                {
                    "code": "InvalidPocketFilter"
                },
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "DuplicatePocket"
                }
            ],
            "name": "CreatePocket",
            "parameters": [
                {
                    "doc": "The name of the pocket. It must be unique within series, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series to create the pocket in.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of components the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "type": "list"
                },
                {
                    "doc": "A list of architectures the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "type": "list"
                },
                {
                    "doc": "The pocket mode. Can be 'pull', 'mirror' and 'upload'.",
                    "name": "mode",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the GPG key to use to sign packages lists for this pocket. The GPG key provided must have a private key associated with it.",
                    "name": "gpg_key",
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). It's 'false' by default.",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The repository entry under dists/ to mirror for pockets in 'mirror' mode. This parameter is optional and defaults to the same name as local series and pocket. If the suite name ends with a '/', the remote repository is flat (packages are not grouped in components); in this case a single value can be passed for the 'components' parameter. Packages from the remote repository will be mirrored in the specified component.",
                    "name": "mirror_suite",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored archive signature. If none is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the series pull_pocket belongs to. Must be a series in the same distribution series belongs to. If not specified, it defaults to series.",
                    "name": "pull_series",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of a pocket in current distribution to sync packages from for pockets in 'pull' mode.",
                    "name": "pull_pocket",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "If specified, the type of the filter of the pocket. Can be either 'whitelist' or 'blacklist'.",
                    "name": "filter_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "For pockets in upload mode, a boolean indicating whether uploaded packages are required to be signed or not. It's 'false' by default.",
                    "name": "upload_allow_unsigned",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a pocket associated with a series in the account.",
            "errors": [
                {
                    "code": "InvalidPocketFilter"
                },
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "DuplicatePocket"
                }
            ],
            "name": "CreatePocket",
            "parameters": [
                {
                    "doc": "The name of the pocket. It must be unique within series, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series to create the pocket in.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of components the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "type": "list"
                },
                {
                    "doc": "A list of architectures the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "type": "list"
                },
                {
                    "doc": "The pocket mode. Can be 'pull', 'mirror' and 'upload'.",
                    "name": "mode",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the GPG key to use to sign packages lists for this pocket. The GPG key provided must have a private key associated with it.",
                    "name": "gpg_key",
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). It's 'false' by default.",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The repository entry under dists/ to mirror for pockets in 'mirror' mode. This parameter is optional and defaults to the same name as local series and pocket. If the suite name ends with a '/', the remote repository is flat (packages are not grouped in components); in this case a single value can be passed for the 'components' parameter. Packages from the remote repository will be mirrored in the specified component.",
                    "name": "mirror_suite",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored archive signature. If none is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the series pull_pocket belongs to. Must be a series in the same distribution series belongs to. If not specified, it defaults to series.",
                    "name": "pull_series",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of a pocket in current distribution to sync packages from for pockets in 'pull' mode.",
                    "name": "pull_pocket",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "If specified, the type of the filter of the pocket. Can be either 'whitelist' or 'blacklist'.",
                    "name": "filter_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "For pockets in upload mode, a boolean indicating whether uploaded packages are required to be signed or not. It's 'false' by default.",
                    "name": "upload_allow_unsigned",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "CreateRemovalProfile": {
        "2011-08-01": {
            "doc": "Create a removal profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidDaysWithoutExchangeValue"
                }
            ],
            "name": "CreateRemovalProfile",
            "parameters": [
                {
                    "doc": "The title of the profile to create.",
                    "name": "title",
                    "type": "unicode"
                },
                {
                    "doc": "The length of time after which a computer may be removed.",
                    "name": "days_without_exchange",
                    "type": "integer"
                },
                {
                    "default": "global",
                    "doc": "An optional name of an access group the profile will apply to.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a removal profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidDaysWithoutExchangeValue"
                }
            ],
            "name": "CreateRemovalProfile",
            "parameters": [
                {
                    "doc": "The title of the profile to create.",
                    "name": "title",
                    "type": "unicode"
                },
                {
                    "doc": "The length of time after which a computer may be removed.",
                    "name": "days_without_exchange",
                    "type": "integer"
                },
                {
                    "default": "global",
                    "doc": "An optional name of an access group the profile will apply to.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateRepositoryProfile": {
        "2011-08-01": {
            "doc": "Create a repository profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "CreateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Title of the repository profile. It must start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Description of the repository profile.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "Optional name of the access group to create the profile in.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a repository profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "CreateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Title of the repository profile. It must start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Description of the repository profile.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": "global",
                    "doc": "Optional name of the access group to create the profile in.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateRole": {
        "2011-08-01": {
            "doc": "Create a new access role.",
            "errors": [
                {
                    "code": "InvalidRoleName"
                },
                {
                    "code": "DuplicateRoleName"
                }
            ],
            "name": "CreateRole",
            "parameters": [
                {
                    "doc": "The name of the role.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The description of the role.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a new access role.",
            "errors": [
                {
                    "code": "InvalidRoleName"
                },
                {
                    "code": "DuplicateRoleName"
                }
            ],
            "name": "CreateRole",
            "parameters": [
                {
                    "doc": "The name of the role.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The description of the role.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateSavedSearch": {
        "2011-08-01": {
            "doc": "Create a new saved search associated with the current account.\n        ",
            "errors": [
                {
                    "code": "InvalidSavedSearchName"
                },
                {
                    "code": "DuplicateSavedSearch"
                },
                {
                    "code": "InvalidSavedSearchCriteria"
                }
            ],
            "name": "CreateSavedSearch",
            "parameters": [
                {
                    "default": None,
                    "doc": "The \"slug\" name for this saved search. It must consist of only lowercase ASCII letters, numbers and hyphens. This is the text which must be used when using the \"search:name\" syntax.  If this parameter is not included a name will be generated automatically based on the title.",
                    "name": "name",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "doc": "The display name for the SavedSearch.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The search string to save.",
                    "name": "search",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a new saved search associated with the current account.\n        ",
            "errors": [
                {
                    "code": "InvalidSavedSearchName"
                },
                {
                    "code": "DuplicateSavedSearch"
                },
                {
                    "code": "InvalidSavedSearchCriteria"
                }
            ],
            "name": "CreateSavedSearch",
            "parameters": [
                {
                    "default": None,
                    "doc": "The \"slug\" name for this saved search. It must consist of only lowercase ASCII letters, numbers and hyphens. This is the text which must be used when using the \"search:name\" syntax.  If this parameter is not included a name will be generated automatically based on the title.",
                    "name": "name",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "doc": "The display name for the SavedSearch.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The search string to save.",
                    "name": "search",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateScript": {
        "2011-08-01": {
            "doc": "Create a new script.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "EmptyScriptInterpreter"
                },
                {
                    "code": "ScriptEncoding"
                },
                {
                    "code": "EmptyScriptCode"
                }
            ],
            "name": "CreateScript",
            "parameters": [
                {
                    "doc": "The title of the new script.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "Amount of time to wait for the process to end.",
                    "name": "time_limit",
                    "type": "integer"
                },
                {
                    "doc": "The filename holding the script contents.",
                    "name": "code",
                    "type": "data"
                },
                {
                    "default": None,
                    "doc": "The user to execute the script as.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The access group for the new script.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create a new script.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "EmptyScriptInterpreter"
                },
                {
                    "code": "ScriptEncoding"
                },
                {
                    "code": "EmptyScriptCode"
                }
            ],
            "name": "CreateScript",
            "parameters": [
                {
                    "doc": "The title of the new script.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "Amount of time to wait for the process to end.",
                    "name": "time_limit",
                    "type": "integer"
                },
                {
                    "doc": "The filename holding the script contents.",
                    "name": "code",
                    "type": "data"
                },
                {
                    "default": None,
                    "doc": "The user to execute the script as.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The access group for the new script.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "CreateScriptAttachment": {
        "2011-08-01": {
            "doc": "Add a script attachment.",
            "errors": [
                {
                    "code": "TooManyScriptAttachments"
                },
                {
                    "code": "ScriptAttachmentSize"
                },
                {
                    "code": "DuplicateScriptAttachment"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "CreateScriptAttachment",
            "parameters": [
                {
                    "doc": "The identity of the script to add the attachment to.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The file to attach",
                    "name": "file",
                    "type": "file"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Add a script attachment.",
            "errors": [
                {
                    "code": "TooManyScriptAttachments"
                },
                {
                    "code": "ScriptAttachmentSize"
                },
                {
                    "code": "DuplicateScriptAttachment"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "CreateScriptAttachment",
            "parameters": [
                {
                    "doc": "The identity of the script to add the attachment to.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The file to attach",
                    "name": "file",
                    "type": "file"
                }
            ],
            "result": {}
        }
    },
    "CreateSeries": {
        "2011-08-01": {
            "doc": "\n    Create a series associated with a distribution in the account.\n    ",
            "errors": [
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "DuplicateSeries"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "CreateSeries",
            "parameters": [
                {
                    "doc": "The name of the series. It must be unique within series within the distribution, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution to create the series in.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Pockets that will be created in the series, they will be in mirror mode by default.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of components for the created pockets. This parameter is **optional** if no pocket is specified.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of architectures for the created pockets. This parameter is **optional** if no pocket is specified",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to sign packages lists of the created pockets. This parameter is **optional** if no pocket is specified.",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for the created pockets. This parameter is **optional** if no pocket is specified.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The remote series to mirror. If not specified, it defaults to the name of the series being created. If a pockets parameter also passed, each of the created pockets will mirror the relevant dists/<mirror_series>-<pocket> repository of the remote archive.",
                    "name": "mirror_series",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored repositories for created pockets. If none is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). It's 'false' by default.",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Create a series associated with a distribution in the account.\n    ",
            "errors": [
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "DuplicateSeries"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "CreateSeries",
            "parameters": [
                {
                    "doc": "The name of the series. It must be unique within series within the distribution, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution to create the series in.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Pockets that will be created in the series, they will be in mirror mode by default.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of components for the created pockets. This parameter is **optional** if no pocket is specified.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of architectures for the created pockets. This parameter is **optional** if no pocket is specified",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to sign packages lists of the created pockets. This parameter is **optional** if no pocket is specified.",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for the created pockets. This parameter is **optional** if no pocket is specified.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The remote series to mirror. If not specified, it defaults to the name of the series being created. If a pockets parameter also passed, each of the created pockets will mirror the relevant dists/<mirror_series>-<pocket> repository of the remote archive.",
                    "name": "mirror_series",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored repositories for created pockets. If none is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). It's 'false' by default.",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "CreateUpgradeProfile": {
        "2011-08-01": {
            "doc": "Create an upgrade profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidScheduleFormat"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidDeliverDelayWindow"
                }
            ],
            "name": "CreateUpgradeProfile",
            "parameters": [
                {
                    "doc": "A human readable title for this upgrade profile.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The frequency at which you wish this upgrade profile to be executed. Valid choices are \"hour\" and \"week\".",
                    "name": "every",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of days of the week on which the upgrade profile will be run. The day names must be abbreviated to their first two letters, as: \"mo\", \"tu\", \"we\", \"th\", \"fr\", \"sa\", \"su\". Required when the every parameter is \"week\" but optional when the every parameter is  \"hour\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "on_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The hour, in 24h format, at which the upgrade profile will be run.",
                    "name": "at_hour",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "doc": "The minute of the hour (0-59) at which the upgrade profile will be run.",
                    "name": "at_minute",
                    "type": "integer"
                },
                {
                    "default": 1,
                    "doc": "An optional number of hours within which the upgrade task should be delivered to computers. The window will be from the time specified by this API call (on_days, at_hour, at_minute) until the provided number of hours later. Defaults to 1 hour.",
                    "name": "deliver_within",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given timeframe specified in minutes.",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "(Deprecated) Whether this upgrade is a security upgrade or not.",
                    "name": "security_upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The type of upgrade profile, either \"security\" or \"all\".",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether this upgrade should also autoremove old packages.",
                    "name": "autoremove",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the profile into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Create an upgrade profile.",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidScheduleFormat"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidDeliverDelayWindow"
                }
            ],
            "name": "CreateUpgradeProfile",
            "parameters": [
                {
                    "doc": "A human readable title for this upgrade profile.",
                    "name": "title",
                    "type": "unicode title"
                },
                {
                    "doc": "The frequency at which you wish this upgrade profile to be executed. Valid choices are \"hour\" and \"week\".",
                    "name": "every",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of days of the week on which the upgrade profile will be run. The day names must be abbreviated to their first two letters, as: \"mo\", \"tu\", \"we\", \"th\", \"fr\", \"sa\", \"su\". Required when the every parameter is \"week\" but optional when the every parameter is  \"hour\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "on_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The hour, in 24h format, at which the upgrade profile will be run.",
                    "name": "at_hour",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "doc": "The minute of the hour (0-59) at which the upgrade profile will be run.",
                    "name": "at_minute",
                    "type": "integer"
                },
                {
                    "default": 1,
                    "doc": "An optional number of hours within which the upgrade task should be delivered to computers. The window will be from the time specified by this API call (on_days, at_hour, at_minute) until the provided number of hours later. Defaults to 1 hour.",
                    "name": "deliver_within",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given timeframe specified in minutes.",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "(Deprecated) Whether this upgrade is a security upgrade or not.",
                    "name": "security_upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The type of upgrade profile, either \"security\" or \"all\".",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default":False,
                    "doc": "Whether this upgrade should also autoremove old packages.",
                    "name": "autoremove",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": "global",
                    "doc": "An optional name of the access group to create the profile into.",
                    "name": "access_group",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "DeriveSeries": {
        "2011-08-01": {
            "doc": "\n    Derive a series from another one in the same distribution. The derived\n    series will have pockets with names corresponding to the origin series,\n    each one configured to pull from the pocket in origin series.\n    ",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "DuplicateSeries"
                },
                {
                    "code": "EmptySeries"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "DeriveSeries",
            "parameters": [
                {
                    "doc": "The name of the derived series. It must be unique within the distribution, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the origin series.",
                    "name": "origin",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution to derive the series in.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Derive a series from another one in the same distribution. The derived\n    series will have pockets with names corresponding to the origin series,\n    each one configured to pull from the pocket in origin series.\n    ",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "DuplicateSeries"
                },
                {
                    "code": "EmptySeries"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "DeriveSeries",
            "parameters": [
                {
                    "doc": "The name of the derived series. It must be unique within the distribution, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the origin series.",
                    "name": "origin",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution to derive the series in.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "DiffPullPocket": {
        "2011-08-01": {
            "doc": "\n    Return a list of the changes between a pocket configured in pull mode and\n    its origin one.\n    ",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "DiffPullPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Return a list of the changes between a pocket configured in pull mode and\n    its origin one.\n    ",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "DiffPullPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "DisableAdministrator": {
        "2011-08-01": {
            "doc": "Disable an administrator of your account.",
            "errors": [
                {
                    "code": "PersonNotMemberOfAccount"
                },
                {
                    "code": "UnknownUser"
                }
            ],
            "name": "DisableAdministrator",
            "parameters": [
                {
                    "doc": "The name of the person to disable.",
                    "name": "email",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Disable an administrator of your account.",
            "errors": [
                {
                    "code": "PersonNotMemberOfAccount"
                },
                {
                    "code": "UnknownUser"
                }
            ],
            "name": "DisableAdministrator",
            "parameters": [
                {
                    "doc": "The name of the person to disable.",
                    "name": "email",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "DisassociateAlert": {
        "2011-08-01": {
            "doc": "Disassociate an alert from computers with specific tags or from\n        all computers.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "InvalidAlertTypeError"
                }
            ],
            "name": "DisassociateAlert",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Disassociate an alert from computers with specific tags or from\n        all computers.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "InvalidAlertTypeError"
                }
            ],
            "name": "DisassociateAlert",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "DisassociatePackageProfile": {
        "2011-08-01": {
            "doc": "Disassociate package profile from computers with specified\n            tags or from all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "DisassociatePackageProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Disassociate package profile from computers with specified\n            tags or from all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "DisassociatePackageProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "DisassociateRemovalProfile": {
        "2011-08-01": {
            "doc": "\n    Disassociate a removal profile from computers with the specified\n    tags, or from all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "DisassociateRemovalProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Disassociate a removal profile from computers with the specified\n    tags, or from all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "DisassociateRemovalProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "DisassociateRepositoryProfile": {
        "2011-08-01": {
            "doc": "Disassociate repository profile from computers with specified\n            tags or from all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRepositoryProfile"
                }
            ],
            "name": "DisassociateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Disassociate repository profile from computers with specified\n            tags or from all computers.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownRepositoryProfile"
                }
            ],
            "name": "DisassociateRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "DisassociateUpgradeProfile": {
        "2011-08-01": {
            "doc": "\n    Disassociate an upgrade profile from computers with the specified\n    tags, or from all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "DisassociateUpgradeProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Disassociate an upgrade profile from computers with the specified\n    tags, or from all computers.\n\n    tags and all_computers=true are mutually exclusive.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownTag"
                },
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "DisassociateUpgradeProfile",
            "parameters": [
                {
                    "doc": "Name of the entity.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Tags to change entity association for",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If True, change the 'all_computers' flag state for the entity. If the flag is enabled, associated tags will be kept, but they will not be effective until the flag is disabled.",
                    "name": "all_computers",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "EditPackageProfile": {
        "2011-08-01": {
            "doc": "\n    Add or remove constraints related to a package profile. Constraints can\n    be dependencies or conflicts.",
            "errors": [
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "InvalidConstraintType"
                }
            ],
            "name": "EditPackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the package profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to add in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "add_constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to remove in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "remove_constraints",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Add or remove constraints related to a package profile. Constraints can\n    be dependencies or conflicts.",
            "errors": [
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "InvalidConstraintType"
                }
            ],
            "name": "EditPackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the package profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to add in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "add_constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to remove in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "remove_constraints",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "EditPocket": {
        "2011-08-01": {
            "doc": "Edit configuration for a repository pocket from a series in a distribution.",
            "errors": [
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "EditPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of components the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "A list of architectures the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to sign packages lists for this pocket. The GPG key provided must have a private key associated with it.",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The repository entry under dists/ to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_suite",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored archive signature. If '-' is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "For pockets in upload mode, a boolean indicating whether uploaded packages are required to be signed or not.",
                    "name": "upload_allow_unsigned",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). ",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit configuration for a repository pocket from a series in a distribution.",
            "errors": [
                {
                    "code": "GPGKeyHasNoSecret"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "EditPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of components the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "components",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "A list of architectures the pocket will handle.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "architectures",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to sign packages lists for this pocket. The GPG key provided must have a private key associated with it.",
                    "name": "gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The URI to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_uri",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The repository entry under dists/ to mirror for pockets in 'mirror' mode.",
                    "name": "mirror_suite",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The name of the GPG key to use to verify the mirrored archive signature. If '-' is given, the stock Ubuntu archive one will be used.",
                    "name": "mirror_gpg_key",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "For pockets in upload mode, a boolean indicating whether uploaded packages are required to be signed or not.",
                    "name": "upload_allow_unsigned",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "Whether the pocket should include selected components also for .udeb packages (debian-installer). ",
                    "name": "include_udeb",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "EditRemovalProfile": {
        "2011-08-01": {
            "doc": "Edit an removal profile.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidDaysWithoutExchangeValue"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "EditRemovalProfile",
            "parameters": [
                {
                    "doc": "The name of the profile to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The length of time after which a computer may be removed.",
                    "name": "days_without_exchange",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit an removal profile.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidDaysWithoutExchangeValue"
                },
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "EditRemovalProfile",
            "parameters": [
                {
                    "doc": "The name of the profile to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The length of time after which a computer may be removed.",
                    "name": "days_without_exchange",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "EditRepositoryProfile": {
        "2011-08-01": {
            "doc": "Edit a repository profile.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "EditRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Title of the repository profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Description of the repository profile.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit a repository profile.",
            "errors": [
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "EditRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile to edit.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Title of the repository profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Description of the repository profile.",
                    "name": "description",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "EditSavedSearch": {
        "2011-08-01": {
            "doc": "Edit a saved search associated with the current account.",
            "errors": [
                {
                    "code": "UnknownSavedSearch"
                },
                {
                    "code": "DuplicateSavedSearch"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidSavedSearchCriteria"
                }
            ],
            "name": "EditSavedSearch",
            "parameters": [
                {
                    "doc": "The \"slug\" name for this saved search, this is the text which must be used when using the \"search:name\" syntax. A saved search with this name must already exist in the account.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new display name for the saved search. If this parameter is not included then the title will not be modified.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "The search string to save. If this parameter is not included then the search string will not be modified.",
                    "name": "search",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit a saved search associated with the current account.",
            "errors": [
                {
                    "code": "UnknownSavedSearch"
                },
                {
                    "code": "DuplicateSavedSearch"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidSavedSearchCriteria"
                }
            ],
            "name": "EditSavedSearch",
            "parameters": [
                {
                    "doc": "The \"slug\" name for this saved search, this is the text which must be used when using the \"search:name\" syntax. A saved search with this name must already exist in the account.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new display name for the saved search. If this parameter is not included then the title will not be modified.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "The search string to save. If this parameter is not included then the search string will not be modified.",
                    "name": "search",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "EditScript": {
        "2011-08-01": {
            "doc": "Edit a script.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "EmptyScriptInterpreter"
                },
                {
                    "code": "ScriptEncoding"
                },
                {
                    "code": "EmptyScriptCode"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "EditScript",
            "parameters": [
                {
                    "doc": "The identifier of the script you wish to edit.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The new script title.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Amount of time to wait for the process to end.",
                    "name": "time_limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The filename holding the script contents.",
                    "name": "code",
                    "optional": True,
                    "type": "data"
                },
                {
                    "default": None,
                    "doc": "The user to execute the script as.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit a script.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateScript"
                },
                {
                    "code": "EmptyScriptInterpreter"
                },
                {
                    "code": "ScriptEncoding"
                },
                {
                    "code": "EmptyScriptCode"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "EditScript",
            "parameters": [
                {
                    "doc": "The identifier of the script you wish to edit.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The new script title.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "Amount of time to wait for the process to end.",
                    "name": "time_limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The filename holding the script contents.",
                    "name": "code",
                    "optional": True,
                    "type": "data"
                },
                {
                    "default": None,
                    "doc": "The user to execute the script as.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "EditUpgradeProfile": {
        "2011-08-01": {
            "doc": "Edit an upgrade profile.",
            "errors": [
                {
                    "code": "UnknownUpgradeProfile"
                },
                {
                    "code": "InvalidDeliverDelayWindow"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidScheduleFormat"
                }
            ],
            "name": "EditUpgradeProfile",
            "parameters": [
                {
                    "doc": "The name for this upgrade profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the upgrade profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "The frequency at which you wish this upgrade profile to be executed. Valid choices are \"hour\" and \"week\".",
                    "name": "every",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of days of the week on which the upgrade profile will be run. The day names must be abbreviated to their first two letters, as: \"mo\", \"tu\", \"we\", \"th\", \"fr\", \"sa\", \"su\". Required when the every parameter is \"week\" but optional when the every parameter is  \"hour\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "on_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The hour, in 24h format, at which the upgrade profile will be run.",
                    "name": "at_hour",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The minute of the hour (0-59) at which the upgrade profile will be run.",
                    "name": "at_minute",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1,
                    "doc": "An optional number of hours within which the upgrade task should be delivered to computers. The window will be from the time specified by this API call (on_days, at_hour, at_minute) until the provided number of hours later. Defaults to 1 hour.",
                    "name": "deliver_within",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "Randomise delivery within the given timeframe specified in minutes.",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "(Deprecated) Whether this upgrade is a security upgrade or not.",
                    "name": "security_upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The type of upgrade profile, either \"security\" or \"all\".",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Whether this upgrade should also autoremove old packages.",
                    "name": "autoremove",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Edit an upgrade profile.",
            "errors": [
                {
                    "code": "UnknownUpgradeProfile"
                },
                {
                    "code": "InvalidDeliverDelayWindow"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "InvalidParameterCombination"
                },
                {
                    "code": "InvalidScheduleFormat"
                }
            ],
            "name": "EditUpgradeProfile",
            "parameters": [
                {
                    "doc": "The name for this upgrade profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the upgrade profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": None,
                    "doc": "The frequency at which you wish this upgrade profile to be executed. Valid choices are \"hour\" and \"week\".",
                    "name": "every",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "A list of days of the week on which the upgrade profile will be run. The day names must be abbreviated to their first two letters, as: \"mo\", \"tu\", \"we\", \"th\", \"fr\", \"sa\", \"su\". Required when the every parameter is \"week\" but optional when the every parameter is  \"hour\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "on_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The hour, in 24h format, at which the upgrade profile will be run.",
                    "name": "at_hour",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The minute of the hour (0-59) at which the upgrade profile will be run.",
                    "name": "at_minute",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1,
                    "doc": "An optional number of hours within which the upgrade task should be delivered to computers. The window will be from the time specified by this API call (on_days, at_hour, at_minute) until the provided number of hours later. Defaults to 1 hour.",
                    "name": "deliver_within",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "Randomise delivery within the given timeframe specified in minutes.",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "(Deprecated) Whether this upgrade is a security upgrade or not.",
                    "name": "security_upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "The type of upgrade profile, either \"security\" or \"all\".",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "Whether this upgrade should also autoremove old packages.",
                    "name": "autoremove",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "ExecuteScript": {
        "2011-08-01": {
            "doc": "Execute a script on computers.",
            "errors": [
                {
                    "code": "RequiresUser"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownScript"
                },
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputers"
                }
            ],
            "name": "ExecuteScript",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to execute the script on.   Multiple occurrences will be joined with a logical AND.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "The identity of the script stored in the server.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The username to execute the script as on the client. Required if the script has no default username.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Execute a script on computers.",
            "errors": [
                {
                    "code": "RequiresUser"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownScript"
                },
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputers"
                }
            ],
            "name": "ExecuteScript",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to execute the script on.   Multiple occurrences will be joined with a logical AND.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "The identity of the script stored in the server.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The username to execute the script as on the client. Required if the script has no default username.",
                    "name": "username",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "GetAPTSources": {
        "2011-08-01": {
            "doc": "\n        Get a list of apt sources in the account used for authentication.\n        ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                }
            ],
            "name": "GetAPTSources",
            "parameters": [
                {
                    "default": [],
                    "doc": "List of names of the APT source to be returned. Multiple names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n        Get a list of apt sources in the account used for authentication.\n        ",
            "errors": [
                {
                    "code": "UnknownAccessGroup"
                }
            ],
            "name": "GetAPTSources",
            "parameters": [
                {
                    "default": [],
                    "doc": "List of names of the APT source to be returned. Multiple names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetAccessGroups": {
        "2011-08-01": {
            "doc": "List all access groups in the account.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "GetAccessGroups",
            "parameters": [
                {
                    "default": [],
                    "doc": "The name of the access group.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "List all access groups in the account.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "GetAccessGroups",
            "parameters": [
                {
                    "default": [],
                    "doc": "The name of the access group.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetActivities": {
        "2011-08-01": {
            "doc": "\n    Retrieve activities associated with the current account, ordered by\n    creation time.\n\n    Some activities requested take an extended period of time to complete.\n    These activities will not have discrete activity_status values. Instead\n    they will report estimated percent complete in the progress field for the\n    activity. The progress field will have one of the following values::\n\n      0: if activity is not started\n      -1: if an error occurred\n      1 to 100: percent complete of ongoing activity\n\n    Common examples of activities with progress would be syncing a pocket\n    repository mirror or provisioning a new system.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "GetActivities",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Retrieve activities associated with the current account, ordered by\n    creation time.\n\n    Some activities requested take an extended period of time to complete.\n    These activities will not have discrete activity_status values. Instead\n    they will report estimated percent complete in the progress field for the\n    activity. The progress field will have one of the following values::\n\n      0: if activity is not started\n      -1: if an error occurred\n      1 to 100: percent complete of ongoing activity\n\n    Common examples of activities with progress would be syncing a pocket\n    repository mirror or provisioning a new system.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "GetActivities",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetActivityTypes": {
        "2011-08-01": {
            "doc": "\n    Retrieve a list of possible activity types for use with the *type:* query\n    criteria.\n    ",
            "errors": [],
            "name": "GetActivityTypes",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Retrieve a list of possible activity types for use with the *type:* query\n    criteria.\n    ",
            "errors": [],
            "name": "GetActivityTypes",
            "parameters": [],
            "result": {}
        }
    },
    "GetAdministrators": {
        "2011-08-01": {
            "doc": "Retrieve the list of administrators in the account.",
            "errors": [],
            "name": "GetAdministrators",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Retrieve the list of administrators in the account.",
            "errors": [],
            "name": "GetAdministrators",
            "parameters": [],
            "result": {}
        }
    },
    "GetAlertSubscribers": {
        "2011-08-01": {
            "doc": "Get a a list of people who subscribe to a given alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                }
            ],
            "name": "GetAlertSubscribers",
            "parameters": [
                {
                    "doc": "The alert type to check the subscription on.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get a a list of people who subscribe to a given alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                }
            ],
            "name": "GetAlertSubscribers",
            "parameters": [
                {
                    "doc": "The alert type to check the subscription on.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "GetAlerts": {
        "2011-08-01": {
            "doc": "Get a list of alerts in an account.",
            "errors": [],
            "name": "GetAlerts",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get a list of alerts in an account.",
            "errors": [],
            "name": "GetAlerts",
            "parameters": [],
            "result": {}
        }
    },
    "GetCSVComplianceData": {
        "2011-08-01": {
            "doc": "Return a CSV formatted report of compliance data.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetCSVComplianceData",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Return a CSV formatted report of compliance data.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetCSVComplianceData",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetComputers": {
        "2011-08-01": {
            "doc": "\n    Get a list of computers associated with the account.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetComputers",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all network devices attached to the computer.",
                    "name": "with_network",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all hardware information known.",
                    "name": "with_hardware",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all custom annotation information known.",
                    "name": "with_annotations",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Get a list of computers associated with the account.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetComputers",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all network devices attached to the computer.",
                    "name": "with_network",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all hardware information known.",
                    "name": "with_hardware",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default":False,
                    "doc": "If True, include the details of all custom annotation information known.",
                    "name": "with_annotations",
                    "optional": True,
                    "type": "boolean"
                }
            ],
            "result": {}
        }
    },
    "GetComputersNotUpgraded": {
        "2011-08-01": {
            "doc": "Report the ids of computers, within a given selection, that are not covered by an upgrade profile.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetComputersNotUpgraded",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Report the ids of computers, within a given selection, that are not covered by an upgrade profile.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetComputersNotUpgraded",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetDistributions": {
        "2011-08-01": {
            "doc": "Get info about distributions.",
            "errors": [],
            "name": "GetDistributions",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of distribution names to get info for. If this is not provided, the call will return all distributions for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get info about distributions.",
            "errors": [],
            "name": "GetDistributions",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of distribution names to get info for. If this is not provided, the call will return all distributions for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetEventLog": {
        "2011-08-01": {
            "doc": "Retrieve event log for the account.",
            "errors": [
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "GetEventLog",
            "parameters": [
                {
                    "default": None,
                    "doc": "The number of days prior to today from which to fetch log entries. It defaults to 30 days.",
                    "name": "days",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Retrieve event log for the account.",
            "errors": [
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "GetEventLog",
            "parameters": [
                {
                    "default": None,
                    "doc": "The number of days prior to today from which to fetch log entries. It defaults to 30 days.",
                    "name": "days",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetGPGKeys": {
        "2011-08-01": {
            "doc": "Get info about GPG keys.",
            "errors": [],
            "name": "GetGPGKeys",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of GPG keys to get info for. If this is not provided, the call will return all keys for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get info about GPG keys.",
            "errors": [],
            "name": "GetGPGKeys",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of GPG keys to get info for. If this is not provided, the call will return all keys for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetJujuEnvironments": {
        "2011-08-01": {
            "doc": "Get the details of all the Juju environments in the account.",
            "errors": [],
            "name": "GetJujuEnvironments",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get the details of all the Juju environments in the account.",
            "errors": [],
            "name": "GetJujuEnvironments",
            "parameters": [],
            "result": {}
        }
    },
    "GetJujuModels": {
        "2011-08-01": {
            "doc": "Get the details of all the Juju models in the account.",
            "errors": [],
            "name": "GetJujuModels",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get the details of all the Juju models in the account.",
            "errors": [],
            "name": "GetJujuModels",
            "parameters": [],
            "result": {}
        }
    },
    "GetNotPingingComputers": {
        "2011-08-01": {
            "doc": "Report the ids of computers, within a given selection, that have not pinged the server in a given number of minutes.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetNotPingingComputers",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "doc": "The number of minutes elapsed in which no ping from included computers has been seen.",
                    "name": "since_minutes",
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Report the ids of computers, within a given selection, that have not pinged the server in a given number of minutes.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetNotPingingComputers",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "doc": "The number of minutes elapsed in which no ping from included computers has been seen.",
                    "name": "since_minutes",
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetPackageProfiles": {
        "2011-08-01": {
            "doc": "Get the details of all Package Profiles defined in the account.\n            ",
            "errors": [],
            "name": "GetPackageProfiles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of package profile names to limit the result.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get the details of all Package Profiles defined in the account.\n            ",
            "errors": [],
            "name": "GetPackageProfiles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of package profile names to limit the result.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetPackages": {
        "2011-08-01": {
            "doc": "\n    Get a list of packages associated with the account used for\n    authentication.\n\n    A package is considered installed if dpkg reports it as installed on the\n    system.\n\n    A package is considered available if it can be fetched from an APT\n    source. Note that this means that it's possible for an installed package\n    to be not available.\n\n    A package is considered an upgrade if it's available and if it has a\n    version higher than a non-held installed package with the same name.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownComputers"
                }
            ],
            "name": "GetPackages",
            "parameters": [
                {
                    "doc": "A query string used to select computers to query packages on.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A string to restrict the search to.  All fields are searched, not just those returned. (e.g., description)",
                    "name": "search",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Restrict the search to these package names. ",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "If true only packages in the installed state will be returned, if false only packages not installed will be returned. If not given both installed and not installed packages will be returned.",
                    "name": "installed",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If true only packages in the available state will be returned, if false only packages not available will be returned. If not given both available and not available packages will be returned.",
                    "name": "available",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If True, only installable packages that are upgrades for an for an installed one are returned. IfFalse, only installable packages that are not upgrades are returned. If not given, packages will be returned regardless of wether they are upgrades or not.",
                    "name": "upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If True, only installed packages that are held on computers are returned. IfFalse, only packages that are not held on computers are returned. If not given, packages will be returned regardless of the held state.",
                    "name": "held",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Get a list of packages associated with the account used for\n    authentication.\n\n    A package is considered installed if dpkg reports it as installed on the\n    system.\n\n    A package is considered available if it can be fetched from an APT\n    source. Note that this means that it's possible for an installed package\n    to be not available.\n\n    A package is considered an upgrade if it's available and if it has a\n    version higher than a non-held installed package with the same name.\n    ",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownComputers"
                }
            ],
            "name": "GetPackages",
            "parameters": [
                {
                    "doc": "A query string used to select computers to query packages on.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "A string to restrict the search to.  All fields are searched, not just those returned. (e.g., description)",
                    "name": "search",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "Restrict the search to these package names. ",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "If true only packages in the installed state will be returned, if false only packages not installed will be returned. If not given both installed and not installed packages will be returned.",
                    "name": "installed",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If true only packages in the available state will be returned, if false only packages not available will be returned. If not given both available and not available packages will be returned.",
                    "name": "available",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If True, only installable packages that are upgrades for an for an installed one are returned. IfFalse, only installable packages that are not upgrades are returned. If not given, packages will be returned regardless of wether they are upgrades or not.",
                    "name": "upgrade",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "If True, only installed packages that are held on computers are returned. IfFalse, only packages that are not held on computers are returned. If not given, packages will be returned regardless of the held state.",
                    "name": "held",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetPendingComputers": {
        "2011-08-01": {
            "doc": "\n    Get a list of pending computers associated with the account used for\n    authentication.\n    ",
            "errors": [],
            "name": "GetPendingComputers",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Get a list of pending computers associated with the account used for\n    authentication.\n    ",
            "errors": [],
            "name": "GetPendingComputers",
            "parameters": [],
            "result": {}
        }
    },
    "GetPermissions": {
        "2011-08-01": {
            "doc": "List all available permissions.",
            "errors": [],
            "name": "GetPermissions",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "List all available permissions.",
            "errors": [],
            "name": "GetPermissions",
            "parameters": [],
            "result": {}
        }
    },
    "GetRemovalProfiles": {
        "2011-08-01": {
            "doc": "List all existing removal profiles.",
            "errors": [],
            "name": "GetRemovalProfiles",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "List all existing removal profiles.",
            "errors": [],
            "name": "GetRemovalProfiles",
            "parameters": [],
            "result": {}
        }
    },
    "GetRepositoryProfiles": {
        "2011-08-01": {
            "doc": "Get a list of repository profiles in the account.",
            "errors": [],
            "name": "GetRepositoryProfiles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of repository profile names to get info for. If this is not provided, the call will return all repository profiles for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get a list of repository profiles in the account.",
            "errors": [],
            "name": "GetRepositoryProfiles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of repository profile names to get info for. If this is not provided, the call will return all repository profiles for the account.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetRoles": {
        "2011-08-01": {
            "doc": "Get all available roles.",
            "errors": [],
            "name": "GetRoles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of role names to limit the result.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Get all available roles.",
            "errors": [],
            "name": "GetRoles",
            "parameters": [
                {
                    "default": [],
                    "doc": "A list of role names to limit the result.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "GetSavedSearches": {
        "2011-08-01": {
            "doc": "Retrieve saved searches associated with the current account.",
            "errors": [],
            "name": "GetSavedSearches",
            "parameters": [
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Retrieve saved searches associated with the current account.",
            "errors": [],
            "name": "GetSavedSearches",
            "parameters": [
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetScriptCode": {
        "2011-08-01": {
            "doc": "Retrieve the code portion of a given script.",
            "errors": [
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "GetScriptCode",
            "parameters": [
                {
                    "doc": "The identity of the script you wish to get the code for.",
                    "name": "script_id",
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Retrieve the code portion of a given script.",
            "errors": [
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "GetScriptCode",
            "parameters": [
                {
                    "doc": "The identity of the script you wish to get the code for.",
                    "name": "script_id",
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetScripts": {
        "2011-08-01": {
            "doc": "Retrieve stored scripts associated with the current account.",
            "errors": [],
            "name": "GetScripts",
            "parameters": [
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Retrieve stored scripts associated with the current account.",
            "errors": [],
            "name": "GetScripts",
            "parameters": [
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetSettings": {
        "2011-08-01": {
            "doc": "\n    Get all settings and their value for the current LDS installation.",
            "errors": [],
            "name": "GetSettings",
            "parameters": [],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Get all settings and their value for the current LDS installation.",
            "errors": [],
            "name": "GetSettings",
            "parameters": [],
            "result": {}
        }
    },
    "GetUSNTimeToFix": {
        "2011-08-01": {
            "doc": "Return a break down of machines unpatched periods following a USN release.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetUSNTimeToFix",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": [],
                    "doc": "A list of periods of days to report on USN fixes being applied in",
                    "item": {
                        "type": "integer"
                    },
                    "name": "fixed_in_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The period of days in the past to search for USNs that are pending on a computer.  This is independent of the in_last argument.",
                    "name": "pending_in_days",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The period of days to look into the past to find USN releases to be considered in these statistics.",
                    "name": "in_last",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Return a break down of machines unpatched periods following a USN release.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetUSNTimeToFix",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": [],
                    "doc": "A list of periods of days to report on USN fixes being applied in",
                    "item": {
                        "type": "integer"
                    },
                    "name": "fixed_in_days",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "The period of days in the past to search for USNs that are pending on a computer.  This is independent of the in_last argument.",
                    "name": "pending_in_days",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": None,
                    "doc": "The period of days to look into the past to find USN releases to be considered in these statistics.",
                    "name": "in_last",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "GetUpgradeProfiles": {
        "2011-08-01": {
            "doc": "List all previously created upgrade profiles.",
            "errors": [],
            "name": "GetUpgradeProfiles",
            "parameters": [
                {
                    "default": None,
                    "doc": " The type of upgrade you wish to list. This can be either \"all\" or \"security\", in which case the result will be a list of upgrade profiles with an upgrade type of \"all\" or \"security\" respectively. If omitted, the resulting list will contain all upgrade profiles, regardless of their upgrade type.",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "List all previously created upgrade profiles.",
            "errors": [],
            "name": "GetUpgradeProfiles",
            "parameters": [
                {
                    "default": None,
                    "doc": " The type of upgrade you wish to list. This can be either \"all\" or \"security\", in which case the result will be a list of upgrade profiles with an upgrade type of \"all\" or \"security\" respectively. If omitted, the resulting list will contain all upgrade profiles, regardless of their upgrade type.",
                    "name": "upgrade_type",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "GetUpgradedComputersByFrequency": {
        "2011-08-01": {
            "doc": "Return a dictionary of computer IDs broken down by their upgrade schedule.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetUpgradedComputersByFrequency",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Return a dictionary of computer IDs broken down by their upgrade schedule.",
            "errors": [
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "GetUpgradedComputersByFrequency",
            "parameters": [
                {
                    "default": "",
                    "doc": "A query string with space separated tokens used to filter the returned result objects.",
                    "name": "query",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 1000,
                    "doc": "The maximum number of results returned by the method. It defaults to 1000.",
                    "name": "limit",
                    "optional": True,
                    "type": "integer"
                },
                {
                    "default": 0,
                    "doc": "The offset inside the list of results.",
                    "name": "offset",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "ImportGPGKey": {
        "2011-08-01": {
            "doc": "Import a GPG key.",
            "errors": [
                {
                    "code": "MultipleGPGKey"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateGPGKey"
                },
                {
                    "code": "GPGKeyImportError"
                }
            ],
            "name": "ImportGPGKey",
            "parameters": [
                {
                    "doc": "Name of the GPG key. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The text representation of the key.",
                    "name": "material",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Import a GPG key.",
            "errors": [
                {
                    "code": "MultipleGPGKey"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "DuplicateGPGKey"
                },
                {
                    "code": "GPGKeyImportError"
                }
            ],
            "name": "ImportGPGKey",
            "parameters": [
                {
                    "doc": "Name of the GPG key. It must be unique within the account, start with an alphanumeric character and only contain lowercase letters, numbers and - or + signs.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The text representation of the key.",
                    "name": "material",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "InstallPackages": {
        "2011-08-01": {
            "doc": "Install packages on selected computers.",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownPackages"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "InstallPackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "A list of package names on which to operate. Multiple package names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to perform the package operation.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Install packages on selected computers.",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownPackages"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "InstallPackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "A list of package names on which to operate. Multiple package names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to perform the package operation.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "InviteAdministrator": {
        "2011-08-01": {
            "doc": "Invite an administrator to your account.",
            "errors": [
                {
                    "code": "RepeatedInvitation"
                },
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "InvalidEmailAddress"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "MaximumAccountAdministrators"
                }
            ],
            "name": "InviteAdministrator",
            "parameters": [
                {
                    "doc": "The name of the person to invite.",
                    "name": "name",
                    "type": "unicode line"
                },
                {
                    "doc": "The email address of the administrator, to which the invitation will be send.",
                    "name": "email",
                    "type": "unicode line"
                },
                {
                    "default": [
                        "GlobalAdmin"
                    ],
                    "doc": "If specified, the roles that the administrator is going to have in your account. Default to GlobalAdmin",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "roles",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Invite an administrator to your account.",
            "errors": [
                {
                    "code": "RepeatedInvitation"
                },
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "InvalidEmailAddress"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "MaximumAccountAdministrators"
                }
            ],
            "name": "InviteAdministrator",
            "parameters": [
                {
                    "doc": "The name of the person to invite.",
                    "name": "name",
                    "type": "unicode line"
                },
                {
                    "doc": "The email address of the administrator, to which the invitation will be send.",
                    "name": "email",
                    "type": "unicode line"
                },
                {
                    "default": [
                        "GlobalAdmin"
                    ],
                    "doc": "If specified, the roles that the administrator is going to have in your account. Default to GlobalAdmin",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "roles",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "ListPocket": {
        "2011-08-01": {
            "doc": "Return a list of the packages in a pocket.",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "ListPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Return a list of the packages in a pocket.",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "ListPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "ModifyPackageProfile": {
        "2011-08-01": {
            "doc": "THIS FUNCTION IS DEPRECATED. please use edit-package-profile instead. \n    Add or remove constraints related to a package profile. Constraints can\n    be dependencies or conflicts.",
            "errors": [
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "InvalidConstraintType"
                }
            ],
            "name": "ModifyPackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the package profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to add in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "add_constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to remove in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "remove_constraints",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "THIS FUNCTION IS DEPRECATED. please use edit-package-profile instead. \n    Add or remove constraints related to a package profile. Constraints can\n    be dependencies or conflicts.",
            "errors": [
                {
                    "code": "EmptyPackageProfile"
                },
                {
                    "code": "UnknownPackageProfileName"
                },
                {
                    "code": "MissingParameter"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidPackageConstraint"
                },
                {
                    "code": "InvalidConstraintType"
                }
            ],
            "name": "ModifyPackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "default": None,
                    "doc": "The new title of the package profile.",
                    "name": "title",
                    "optional": True,
                    "type": "unicode title"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to add in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "add_constraints",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default": [],
                    "doc": "List of constraints specifications to remove in the form of \"depends packagename\" or \"conflicts packagename < 1.0\".",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "remove_constraints",
                    "optional": True,
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "PullPackagesToPocket": {
        "2011-08-01": {
            "doc": "\n    Import packages to a pocket in pull mode from its parent pocket.\n    ",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "PullPackagesToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to pull packages to.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Import packages to a pocket in pull mode from its parent pocket.\n    ",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "PullPackagesToPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to pull packages to.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RebootComputers": {
        "2011-08-01": {
            "doc": "Reboot a list of computers.",
            "errors": [
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RebootComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to reboot.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Reboot a list of computers.",
            "errors": [
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RebootComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to reboot.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RegisterJujuEnvironment": {
        "2011-08-01": {
            "doc": "Register a Juju environment.",
            "errors": [
                {
                    "code": "InvalidEnvironmentName"
                },
                {
                    "code": "EnvironmentCredentialsError"
                },
                {
                    "code": "DuplicateEnvironment"
                },
                {
                    "code": "EnvironmentConnectionFailed"
                }
            ],
            "name": "RegisterJujuEnvironment",
            "parameters": [
                {
                    "doc": "The name of the environment.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The endpoint address of the Juju API.",
                    "name": "endpoint",
                    "type": "unicode"
                },
                {
                    "doc": "The username used to authenticate with the Juju API.",
                    "name": "username",
                    "type": "unicode"
                },
                {
                    "doc": "The password used to authenticate with the Juju API.",
                    "name": "password",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Register a Juju environment.",
            "errors": [
                {
                    "code": "InvalidEnvironmentName"
                },
                {
                    "code": "EnvironmentCredentialsError"
                },
                {
                    "code": "DuplicateEnvironment"
                },
                {
                    "code": "EnvironmentConnectionFailed"
                }
            ],
            "name": "RegisterJujuEnvironment",
            "parameters": [
                {
                    "doc": "The name of the environment.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The endpoint address of the Juju API.",
                    "name": "endpoint",
                    "type": "unicode"
                },
                {
                    "doc": "The username used to authenticate with the Juju API.",
                    "name": "username",
                    "type": "unicode"
                },
                {
                    "doc": "The password used to authenticate with the Juju API.",
                    "name": "password",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RegisterJujuModel": {
        "2011-08-01": {
            "doc": "Register a Juju model.",
            "errors": [
                {
                    "code": "DuplicateJujuModel"
                },
                {
                    "code": "InvalidJujuModelName"
                },
                {
                    "code": "JujuControllerCredentialsError"
                },
                {
                    "code": "JujuControllerConnectionFailed"
                }
            ],
            "name": "RegisterJujuModel",
            "parameters": [
                {
                    "doc": "The name of the model.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The endpoint address of the Juju API.",
                    "name": "endpoint",
                    "type": "unicode"
                },
                {
                    "doc": "The username used to authenticate with the Juju API.",
                    "name": "username",
                    "type": "unicode"
                },
                {
                    "doc": "The password used to authenticate with the Juju API.",
                    "name": "password",
                    "type": "unicode"
                },
                {
                    "doc": "The UUID of the model to register from the controller.",
                    "name": "uuid",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Register a Juju model.",
            "errors": [
                {
                    "code": "DuplicateJujuModel"
                },
                {
                    "code": "InvalidJujuModelName"
                },
                {
                    "code": "JujuControllerCredentialsError"
                },
                {
                    "code": "JujuControllerConnectionFailed"
                }
            ],
            "name": "RegisterJujuModel",
            "parameters": [
                {
                    "doc": "The name of the model.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The endpoint address of the Juju API.",
                    "name": "endpoint",
                    "type": "unicode"
                },
                {
                    "doc": "The username used to authenticate with the Juju API.",
                    "name": "username",
                    "type": "unicode"
                },
                {
                    "doc": "The password used to authenticate with the Juju API.",
                    "name": "password",
                    "type": "unicode"
                },
                {
                    "doc": "The UUID of the model to register from the controller.",
                    "name": "uuid",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RejectPendingComputers": {
        "2011-08-01": {
            "doc": "\n    Reject a list of pending computers associated with the account used for\n    authentication.\n    ",
            "errors": [
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RejectPendingComputers",
            "parameters": [
                {
                    "doc": "A list of computer IDs to reject.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Reject a list of pending computers associated with the account used for\n    authentication.\n    ",
            "errors": [
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RejectPendingComputers",
            "parameters": [
                {
                    "doc": "A list of computer IDs to reject.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveAPTSource": {
        "2011-08-01": {
            "doc": "Remove apt source from the account.",
            "errors": [
                {
                    "code": "UnknownAPTSource"
                },
                {
                    "code": "APTSourceInUse"
                }
            ],
            "name": "RemoveAPTSource",
            "parameters": [
                {
                    "doc": "The name of the apt source to be removed.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove apt source from the account.",
            "errors": [
                {
                    "code": "UnknownAPTSource"
                },
                {
                    "code": "APTSourceInUse"
                }
            ],
            "name": "RemoveAPTSource",
            "parameters": [
                {
                    "doc": "The name of the apt source to be removed.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveAPTSourceFromRepositoryProfile": {
        "2011-08-01": {
            "doc": "Remove APT source from a repository profile.\n            An activity will be created to remove the source from the\n            computers associated with the given profile.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "RemoveAPTSourceFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the APT source to remove.",
                    "name": "apt_source",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove APT source from a repository profile.\n            An activity will be created to remove the source from the\n            computers associated with the given profile.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "RemoveAPTSourceFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the APT source to remove.",
                    "name": "apt_source",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveAPTSources": {
        "2011-08-01": {
            "doc": "Deprecated: use RemoveAPTSource instead.",
            "errors": [
                {
                    "code": "UnknownAPTSource"
                },
                {
                    "code": "APTSourceInUse"
                }
            ],
            "name": "RemoveAPTSources",
            "parameters": [
                {
                    "doc": "List of names of the APT sources be removed. Multiple names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Deprecated: use RemoveAPTSource instead.",
            "errors": [
                {
                    "code": "UnknownAPTSource"
                },
                {
                    "code": "APTSourceInUse"
                }
            ],
            "name": "RemoveAPTSources",
            "parameters": [
                {
                    "doc": "List of names of the APT sources be removed. Multiple names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveAPTSourcesFromRepositoryProfile": {
        "2011-08-01": {
            "doc": "\n            Deprecated: use RemoveAPTSourceFromRepositoryProfile instead.\n        ",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "RemoveAPTSourcesFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the APT sources to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "apt_sources",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n            Deprecated: use RemoveAPTSourceFromRepositoryProfile instead.\n        ",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownAPTSource"
                }
            ],
            "name": "RemoveAPTSourcesFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the APT sources to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "apt_sources",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveAccessGroup": {
        "2011-08-01": {
            "doc": "Remove an access group.",
            "errors": [
                {
                    "code": "InvalidAccessGroup"
                },
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveAccessGroup",
            "parameters": [
                {
                    "doc": "The name of the access group to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove an access group.",
            "errors": [
                {
                    "code": "InvalidAccessGroup"
                },
                {
                    "code": "UnknownAccessGroup"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveAccessGroup",
            "parameters": [
                {
                    "doc": "The name of the access group to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveAccessGroupsFromRole": {
        "2011-08-01": {
            "doc": "Remove the given access groups to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownAccessGroups"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "RemoveAccessGroupsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of access groups to remove from the role.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "access_groups",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove the given access groups to a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownAccessGroups"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "RemoveAccessGroupsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of access groups to remove from the role.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "access_groups",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveAnnotationFromComputers": {
        "2011-08-01": {
            "doc": "Remove annotation key from a selection of computers.",
            "errors": [
                {
                    "code": "InvalidAnnotationKey"
                },
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "RemoveAnnotationFromComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers from which to remove annotation.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Annotation key to disassociate.",
                    "name": "key",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove annotation key from a selection of computers.",
            "errors": [
                {
                    "code": "InvalidAnnotationKey"
                },
                {
                    "code": "InvalidQuery"
                }
            ],
            "name": "RemoveAnnotationFromComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers from which to remove annotation.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Annotation key to disassociate.",
                    "name": "key",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveComputers": {
        "2011-08-01": {
            "doc": "Remove a list of computers by ID.",
            "errors": [
                {
                    "code": "UnknownComputer"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "RemoveComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to remove.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a list of computers by ID.",
            "errors": [
                {
                    "code": "UnknownComputer"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                }
            ],
            "name": "RemoveComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to remove.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveDistribution": {
        "2011-08-01": {
            "doc": "Remove the specified repository distribution.",
            "errors": [
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemoveDistribution",
            "parameters": [
                {
                    "doc": "The name of the distribution to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove the specified repository distribution.",
            "errors": [
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemoveDistribution",
            "parameters": [
                {
                    "doc": "The name of the distribution to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveGPGKey": {
        "2011-08-01": {
            "doc": "Remove a GPG key.",
            "errors": [
                {
                    "code": "GPGKeyInUse"
                },
                {
                    "code": "UnknownGPGKey"
                }
            ],
            "name": "RemoveGPGKey",
            "parameters": [
                {
                    "doc": "Name of the GPG key to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a GPG key.",
            "errors": [
                {
                    "code": "GPGKeyInUse"
                },
                {
                    "code": "UnknownGPGKey"
                }
            ],
            "name": "RemoveGPGKey",
            "parameters": [
                {
                    "doc": "Name of the GPG key to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveJujuEnvironment": {
        "2011-08-01": {
            "doc": "Remove a Juju environment from the account.",
            "errors": [
                {
                    "code": "UnknownEnvironment"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                },
                {
                    "code": "JujuModelRemovalError"
                },
                {
                    "code": "EnvironmentRemovalError"
                }
            ],
            "name": "RemoveJujuEnvironment",
            "parameters": [
                {
                    "doc": "Name of the environment to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a Juju environment from the account.",
            "errors": [
                {
                    "code": "UnknownEnvironment"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownEntityIDs"
                },
                {
                    "code": "JujuModelRemovalError"
                },
                {
                    "code": "EnvironmentRemovalError"
                }
            ],
            "name": "RemoveJujuEnvironment",
            "parameters": [
                {
                    "doc": "Name of the environment to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveJujuModel": {
        "2011-08-01": {
            "doc": "Remove a Juju model from the account.",
            "errors": [
                {
                    "code": "UnknownJujuModel"
                },
                {
                    "code": "UnknownEntityIDs"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "JujuModelRemovalError"
                },
                {
                    "code": "EnvironmentRemovalError"
                }
            ],
            "name": "RemoveJujuModel",
            "parameters": [
                {
                    "doc": "Name of the model to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a Juju model from the account.",
            "errors": [
                {
                    "code": "UnknownJujuModel"
                },
                {
                    "code": "UnknownEntityIDs"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "JujuModelRemovalError"
                },
                {
                    "code": "EnvironmentRemovalError"
                }
            ],
            "name": "RemoveJujuModel",
            "parameters": [
                {
                    "doc": "Name of the model to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemovePackageFiltersFromPocket": {
        "2011-08-01": {
            "doc": "\n    Remove package filters from a repository pocket.  The pocket must be in\n    pull mode and support blacklist/whitelist filtering.\n    ",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "NoPocketFiltering"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemovePackageFiltersFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to operate on.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be added or removed from the pocket filter.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Remove package filters from a repository pocket.  The pocket must be in\n    pull mode and support blacklist/whitelist filtering.\n    ",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "NoPocketFiltering"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemovePackageFiltersFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to operate on.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be added or removed from the pocket filter.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemovePackageProfile": {
        "2011-08-01": {
            "doc": "Remove a package profile, given its name.",
            "errors": [
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "RemovePackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a package profile, given its name.",
            "errors": [
                {
                    "code": "UnknownPackageProfileName"
                }
            ],
            "name": "RemovePackageProfile",
            "parameters": [
                {
                    "doc": "The name of the package profile to remove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemovePackages": {
        "2011-08-01": {
            "doc": "Remove packages on selected computers.",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownPackages"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "RemovePackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "A list of package names on which to operate. Multiple package names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to perform the package operation.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove packages on selected computers.",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "UnknownPackages"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "RemovePackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "A list of package names on which to operate. Multiple package names can be supplied.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to perform the package operation.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "RemovePackagesFromPocket": {
        "2011-08-01": {
            "doc": "Remove packages from pockets in upload mode.",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePackagesFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to remove packages from.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be removed from the pockets.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove packages from pockets in upload mode.",
            "errors": [
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePackagesFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to remove packages from.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of names of packages to be removed from the pockets.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemovePermissionsFromRole": {
        "2011-08-01": {
            "doc": "Remove permissions from a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                },
                {
                    "code": "InvalidRolePermissions"
                }
            ],
            "name": "RemovePermissionsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of permissions to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "permissions",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove permissions from a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                },
                {
                    "code": "InvalidRolePermissions"
                }
            ],
            "name": "RemovePermissionsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of permissions to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "permissions",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemovePersonsFromRole": {
        "2011-08-01": {
            "doc": "Remove people from a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownPersonEmails"
                },
                {
                    "code": "SelfRevokeGlobalAdmin"
                }
            ],
            "name": "RemovePersonsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of email addresses of people to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "persons",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove people from a role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "UnknownPersonEmails"
                },
                {
                    "code": "SelfRevokeGlobalAdmin"
                }
            ],
            "name": "RemovePersonsFromRole",
            "parameters": [
                {
                    "doc": "The name of the role to modify.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "A list of email addresses of people to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "persons",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemovePocket": {
        "2011-08-01": {
            "doc": "Remove a repository pocket from a series in a distribution.",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to remove.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a repository pocket from a series in a distribution.",
            "errors": [
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to remove.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemovePocketsFromRepositoryProfile": {
        "2011-08-01": {
            "doc": "Remove repository pockets from a repository profile.\n            An activity will be created to remove the pockets from the APT\n            sources of the computers associated with the given profile.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePocketsFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the pockets to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "type": "list"
                },
                {
                    "doc": "The name of the series the pocket belongs to.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove repository pockets from a repository profile.\n            An activity will be created to remove the pockets from the APT\n            sources of the computers associated with the given profile.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemovePocketsFromRepositoryProfile",
            "parameters": [
                {
                    "doc": "Name of the repository profile.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The names of the pockets to remove.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "pockets",
                    "type": "list"
                },
                {
                    "doc": "The name of the series the pocket belongs to.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution the series belongs to.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveRemovalProfile": {
        "2011-08-01": {
            "doc": "Remove an existing removal profile by name.",
            "errors": [
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "RemoveRemovalProfile",
            "parameters": [
                {
                    "doc": "The name of the removal profile you wish toremove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove an existing removal profile by name.",
            "errors": [
                {
                    "code": "UnknownRemovalProfile"
                }
            ],
            "name": "RemoveRemovalProfile",
            "parameters": [
                {
                    "doc": "The name of the removal profile you wish toremove.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveRepositoryProfile": {
        "2011-08-01": {
            "doc": "Remove repository profile from the account.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveRepositoryProfile",
            "parameters": [
                {
                    "doc": "The name of the repository profile to be removed.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove repository profile from the account.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveRepositoryProfile",
            "parameters": [
                {
                    "doc": "The name of the repository profile to be removed.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveRepositoryProfiles": {
        "2011-08-01": {
            "doc": "Deprecated: use RemoveRepositoryProfile instead.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveRepositoryProfiles",
            "parameters": [
                {
                    "doc": "Names of the repository profiles to be removed.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Deprecated: use RemoveRepositoryProfile instead.",
            "errors": [
                {
                    "code": "UnknownRepositoryProfile"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "RemoveRepositoryProfiles",
            "parameters": [
                {
                    "doc": "Names of the repository profiles to be removed.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "names",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveRole": {
        "2011-08-01": {
            "doc": "Remove an access role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "RemoveRole",
            "parameters": [
                {
                    "doc": "The name of the role.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove an access role.",
            "errors": [
                {
                    "code": "UnknownRole"
                },
                {
                    "code": "ReadOnlyRole"
                }
            ],
            "name": "RemoveRole",
            "parameters": [
                {
                    "doc": "The name of the role.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveSavedSearch": {
        "2011-08-01": {
            "doc": "Remove a saved search associated with the current account.",
            "errors": [
                {
                    "code": "UnknownSavedSearch"
                }
            ],
            "name": "RemoveSavedSearch",
            "parameters": [
                {
                    "doc": "The \"slug\" name for this saved search.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a saved search associated with the current account.",
            "errors": [
                {
                    "code": "UnknownSavedSearch"
                }
            ],
            "name": "RemoveSavedSearch",
            "parameters": [
                {
                    "doc": "The \"slug\" name for this saved search.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveScript": {
        "2011-08-01": {
            "doc": "Remove scripts.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "RemoveScript",
            "parameters": [
                {
                    "doc": "The identity of the script to remove.",
                    "name": "script_id",
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove scripts.",
            "errors": [
                {
                    "code": "Unauthorised"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "RemoveScript",
            "parameters": [
                {
                    "doc": "The identity of the script to remove.",
                    "name": "script_id",
                    "type": "integer"
                }
            ],
            "result": {}
        }
    },
    "RemoveScriptAttachment": {
        "2011-08-01": {
            "doc": "Remove a script attachment.",
            "errors": [
                {
                    "code": "UnknownScriptAttachment"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "RemoveScriptAttachment",
            "parameters": [
                {
                    "doc": "The identity of the script to remove.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The filename of the attachment to remove.",
                    "name": "filename",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove a script attachment.",
            "errors": [
                {
                    "code": "UnknownScriptAttachment"
                },
                {
                    "code": "UnknownScript"
                }
            ],
            "name": "RemoveScriptAttachment",
            "parameters": [
                {
                    "doc": "The identity of the script to remove.",
                    "name": "script_id",
                    "type": "integer"
                },
                {
                    "doc": "The filename of the attachment to remove.",
                    "name": "filename",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveSeries": {
        "2011-08-01": {
            "doc": "\n    Remove a repository series from a distribution.\n    ",
            "errors": [
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemoveSeries",
            "parameters": [
                {
                    "doc": "The name of the series to remove.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Remove a repository series from a distribution.\n    ",
            "errors": [
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "RemoveSeries",
            "parameters": [
                {
                    "doc": "The name of the series to remove.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveTagsFromComputers": {
        "2011-08-01": {
            "doc": "Remove tags from a selection of computers.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTag"
                }
            ],
            "name": "RemoveTagsFromComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to remove tags from.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Tag names to be removed.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove tags from a selection of computers.",
            "errors": [
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTag"
                }
            ],
            "name": "RemoveTagsFromComputers",
            "parameters": [
                {
                    "doc": "A query string used to select the computers to remove tags from.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "doc": "Tag names to be removed.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "tags",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RemoveUpgradeProfile": {
        "2011-08-01": {
            "doc": "Remove an existing upgrade profile by name.",
            "errors": [
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "RemoveUpgradeProfile",
            "parameters": [
                {
                    "doc": "The name of the upgrade profile you wish to cancel.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Remove an existing upgrade profile by name.",
            "errors": [
                {
                    "code": "UnknownUpgradeProfile"
                }
            ],
            "name": "RemoveUpgradeProfile",
            "parameters": [
                {
                    "doc": "The name of the upgrade profile you wish to cancel.",
                    "name": "name",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "RemoveUploaderGPGKeysFromPocket": {
        "2011-08-01": {
            "doc": "\n    Remove GPG keys for uploaded packages validation from a repository pocket\n    in upload mode.\n    ",
            "errors": [
                {
                    "code": "GPGKeyNotAssociated"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "GPGKeyAlreadyAssociated"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemoveUploaderGPGKeysFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket on which to associate keys.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of GPG keys on which to operate.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "gpg_keys",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Remove GPG keys for uploaded packages validation from a repository pocket\n    in upload mode.\n    ",
            "errors": [
                {
                    "code": "GPGKeyNotAssociated"
                },
                {
                    "code": "UnknownSeries"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "UnknownGPGKey"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "GPGKeyAlreadyAssociated"
                },
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "OperationInProgress"
                }
            ],
            "name": "RemoveUploaderGPGKeysFromPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket on which to associate keys.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series containing the pocket.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution containing the series.",
                    "name": "distribution",
                    "type": "unicode"
                },
                {
                    "doc": "A list of GPG keys on which to operate.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "gpg_keys",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "RenameComputers": {
        "2011-08-01": {
            "doc": "Rename a set of computers.",
            "errors": [
                {
                    "code": "InvalidTitle"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RenameComputers",
            "parameters": [
                {
                    "doc": "mapping of computer_ids to computer titles",
                    "key": {
                        "doc": "The ID of the computer to rename",
                        "type": "integer"
                    },
                    "name": "computer_titles",
                    "type": "mapping",
                    "value": {
                        "doc": "The new name to apply.",
                        "type": "unicode"
                    }
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Rename a set of computers.",
            "errors": [
                {
                    "code": "InvalidTitle"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "RenameComputers",
            "parameters": [
                {
                    "doc": "mapping of computer_ids to computer titles",
                    "key": {
                        "doc": "The ID of the computer to rename",
                        "type": "integer"
                    },
                    "name": "computer_titles",
                    "type": "mapping",
                    "value": {
                        "doc": "The new name to apply.",
                        "type": "unicode"
                    }
                }
            ],
            "result": {}
        }
    },
    "SetSettings": {
        "2011-08-01": {
            "doc": "\n    Set configuration settings for the current LDS installation.",
            "errors": [
                {
                    "code": "SettingsValue"
                }
            ],
            "name": "SetSettings",
            "parameters": [
                {
                    "doc": "Key/value pairs to set, separated by '='. 'true' and 'false' strings will be interpreted as booleans.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "key_values",
                    "type": "list"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Set configuration settings for the current LDS installation.",
            "errors": [
                {
                    "code": "SettingsValue"
                }
            ],
            "name": "SetSettings",
            "parameters": [
                {
                    "doc": "Key/value pairs to set, separated by '='. 'true' and 'false' strings will be interpreted as booleans.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "key_values",
                    "type": "list"
                }
            ],
            "result": {}
        }
    },
    "ShutdownComputers": {
        "2011-08-01": {
            "doc": "Shutdown a list of computers.",
            "errors": [
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "ShutdownComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to shutdown.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Shutdown a list of computers.",
            "errors": [
                {
                    "code": "InvalidTime"
                },
                {
                    "code": "UnknownComputer"
                }
            ],
            "name": "ShutdownComputers",
            "parameters": [
                {
                    "doc": "A list of computer ids to shutdown.",
                    "item": {
                        "type": "integer"
                    },
                    "name": "computer_ids",
                    "type": "list"
                },
                {
                    "default": None,
                    "doc": "A time in the future to deliver the script.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "SubscribeToAlert": {
        "2011-08-01": {
            "doc": "Subscribe to an alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "SubscribeToAlert",
            "parameters": [
                {
                    "doc": "The alert type to add a subscription to.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Subscribe to an alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                },
                {
                    "code": "Unauthorised"
                }
            ],
            "name": "SubscribeToAlert",
            "parameters": [
                {
                    "doc": "The alert type to add a subscription to.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "SyncMirrorPocket": {
        "2011-08-01": {
            "doc": "Synchronize a mirror repository pocket.",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "SyncMirrorPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to synchronize.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Synchronize a mirror repository pocket.",
            "errors": [
                {
                    "code": "InvalidPocketMode"
                },
                {
                    "code": "UnknownDistribution"
                },
                {
                    "code": "OperationInProgress"
                },
                {
                    "code": "UnknownPocket"
                },
                {
                    "code": "UnknownSeries"
                }
            ],
            "name": "SyncMirrorPocket",
            "parameters": [
                {
                    "doc": "The name of the pocket to synchronize.",
                    "name": "name",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the series.",
                    "name": "series",
                    "type": "unicode"
                },
                {
                    "doc": "The name of the distribution.",
                    "name": "distribution",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "UnsubscribeFromAlert": {
        "2011-08-01": {
            "doc": "Unsubscribe from an alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                }
            ],
            "name": "UnsubscribeFromAlert",
            "parameters": [
                {
                    "doc": "The alert type to remove a subscription from.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "Unsubscribe from an alert.",
            "errors": [
                {
                    "code": "UnknownAlertTypeError"
                }
            ],
            "name": "UnsubscribeFromAlert",
            "parameters": [
                {
                    "doc": "The alert type to remove a subscription from.",
                    "name": "alert_type",
                    "type": "unicode"
                }
            ],
            "result": {}
        }
    },
    "UpgradePackages": {
        "2011-08-01": {
            "doc": "\n    Request upgrading of all packages identified as being upgradable, on all\n    computers selected by query.\n    ",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "UpgradePackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "List of package names on which to perform an upgrade. Multiple package names can be supplied like packages.1=foo and packages.2=bar.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If 'true' then only packages with USNs, i.e. security upgrades will be applied.",
                    "name": "security_only",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default": None,
                    "doc": "A time in the future to perform the package upgrade.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        },
        "2013-11-04": {
            "doc": "\n    Request upgrading of all packages identified as being upgradable, on all\n    computers selected by query.\n    ",
            "errors": [
                {
                    "code": "UnknownComputers"
                },
                {
                    "code": "InvalidQuery"
                },
                {
                    "code": "InvalidTime"
                }
            ],
            "name": "UpgradePackages",
            "parameters": [
                {
                    "doc": "A qualified criteria to be used in the search.",
                    "name": "query",
                    "type": "unicode"
                },
                {
                    "default": [],
                    "doc": "List of package names on which to perform an upgrade. Multiple package names can be supplied like packages.1=foo and packages.2=bar.",
                    "item": {
                        "type": "unicode"
                    },
                    "name": "packages",
                    "optional": True,
                    "type": "list"
                },
                {
                    "default":False,
                    "doc": "If 'true' then only packages with USNs, i.e. security upgrades will be applied.",
                    "name": "security_only",
                    "optional": True,
                    "type": "boolean"
                },
                {
                    "default":  None,
                    "doc": "A time in the future to perform the package upgrade.",
                    "name": "deliver_after",
                    "optional": True,
                    "type": "unicode"
                },
                {
                    "default": 0,
                    "doc": "Randomise delivery within the given time frame specified in minutes",
                    "name": "deliver_delay_window",
                    "optional": True,
                    "type": "integer"
                }
            ],
            "result": {}
        }
    }
}

class _ErrorsContainer(object):
    """
    A container for Exception subclasses which is used as a fake module object.
    """

    def add_error(self, error_name, error):
        """
        Add an exception to this errors container.
        """

        error.__module__ = __name__ + ".errors"
        setattr(self, error_name, error)

    def lookup_error(self, error_name):
        """
        Find an exception by name. If it's not found, C{None} will be returned.
        """

        return getattr(self, error_name, None)


class HTTPError(Exception):
    """Exception raised when a non-200 status is received.

    @ivar code: The HTTP status code.
    @ivar message: The HTTP response body.
    @ivar message_data: A data structure extracted by parsing the response body
        as JSON, if possible. Otherwise None. Can be overridden by passing the
        C{message_data} parameter.
    @ivar error_code: The value of the "error" key from the message data.
    @ivar error_message: The value of the "message" key from the message data.
    """

    def __init__(self, code, message=None, message_data=None):
        self.code = code
        self.message = message
        self.message_data = None
        self.error_code = None
        self.error_message = None
        if message is not None and message.startswith("{"):
            self.message_data = json.loads(message)
        if message_data:
            self.message_data = message_data
        if self.message_data:
            self.error_code = self.message_data["error"]
            self.error_message = self.message_data["message"]

    def __str__(self):
        s = "<%s code=%s" % (type(self).__name__, self.code)
        if self.error_code is not None:
            s += " error_code=%s error_message=%s" % (
                self.error_code,
                self.error_message,
            )
        else:
            s += " message=%s" % (self.message)
        return s + ">"


class APIError(HTTPError):
    """Exception for a known API error"""


_Action = namedtuple(
    "action", ("name", "method_name", "doc", "required_args", "optional_args")
)


def fetch(url, post_body, headers, connect_timeout=30, total_timeout=600, cainfo=True):
    """
    Wrapper around C{requests.session}, setting up the proper options and timeout.

    @return: The body of the response.
    """

    session = requests.session()

    headers["Content-type"] = "application/x-www-form-urlencoded"
    if headers:
        session.headers.update(headers)

    response = session.post(
        url,
        data=post_body.encode("utf-8"),
        allow_redirects=True,
        timeout=(connect_timeout, total_timeout),
        verify=cainfo,
    )

    if not response.ok:
        raise HTTPError(response.status_code, response.text)

    return response.text


def parse(url):
    """
    Split the given URL into the host, port, and path.

    @type url: C{str}
    @param url: An URL to parse.
    """

    lowurl = url.lower()
    if not lowurl.startswith(("http://", "https://")):
        raise SyntaxError("URL must start with 'http://' or 'https://': %s" % (url,))
    url = url.strip()
    parsed = urlparse(url)
    path = urlunparse(("", "") + parsed[2:])
    host = parsed[1]

    if ":" in host:
        host, port = host.split(":")
        try:
            port = int(port)
        except ValueError:
            port = None
    else:
        port = None

    return str(host), port, str(path)


def run_query(
    access_key,
    secret_key,
    action,
    params,
    uri,
    ssl_ca_file=True,
    version=LATEST_VERSION,
):
    """Make a low-level query against the Landscape API.

    @param access_key: The user access key.
    @param secret_key: The user secret key.
    @param action: The type of methods to call. For example, "GetComputers".
    @param params: A dictionary of the parameters to pass to the action.
    @param uri: The root URI of the API service. For example,
        "https://landscape.canonical.com/".
    @param ssl_ca_file: Path to the server's SSL Certificate Authority
        certificate. For example, "~/landscape_server_ca.crt".
    """

    for key, value in list(params.items()):
        if isinstance(key, str):
            params.pop(key)
            key = str(key)
        if isinstance(value, str):
            value = str(value)
        params[key] = value

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    params.update(
        {
            "access_key_id": access_key,
            "action": action,
            "signature_version": "2",
            "signature_method": "HmacSHA256",
            "timestamp": timestamp,
            "version": version,
        }
    )
    method = "POST"
    host, port, path = parse(uri)
    signed_host = "%s:%d" % (host, port) if port is not None else host
    if not path:
        path = "/"
        uri = "%s/" % uri
    signed_params = "&".join(
        "%s=%s" % (quote(key, safe="~"), quote(value, safe="~"))
        for key, value in sorted(params.items())
    )
    to_sign = "%s\n%s\n%s\n%s" % (method, signed_host, path, signed_params)
    digest = hmac.new(
        secret_key.encode("utf-8"), to_sign.encode("utf-8"), sha256
    ).digest()
    signature = b64encode(digest)
    signed_params += "&signature=%s" % quote(signature)
    try:
        return fetch(uri, signed_params, {"Host": signed_host}, cainfo=ssl_ca_file)
    except HTTPError as e:
        if e.error_code is not None:
            error_class = errors.lookup_error(_get_error_code_name(e.error_code))
            if error_class:
                raise error_class(e.code, e.message)
        raise e


def _get_error_code_name(error_code):
    """
    Get the Python exception name given an error code. If the error code
    doesn't end in "Error", the word "Error" will be appended.
    """

    if error_code.endswith("Error"):
        return error_code
    else:
        return error_code + "Error"


def _lowercase_api_name(name):
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def load_schema():
    """
    Load the schema from the C{schemas.json} file.

    Invoking this method will populate the module-level C{errors} object with
    exception classes based on the schema.
    """
    # this_directory = os.path.dirname(schema_path+"/schemas.json")
    # schema_filename = os.path.join(this_directory, )

    return SCHEMA


def _build_exception(name):
    # TODO: Put __doc__ on the generated errors (must be included in the
    # schema)
    class _APIError(APIError):
        pass

    _APIError.__name__ = str(name)
    return _APIError


def _build_exceptions(schema):
    """
    Given a schema, construct a L{_ErrorsContainer} and populate it with error
    classes based on all the error codes specified in the schema.
    """

    errors = _ErrorsContainer()
    for action, version_handlers in list(schema.items()):
        for version, handler in list(version_handlers.items()):
            for error in handler["errors"]:
                exception_name = _get_error_code_name(error["code"])
                exception_type = _build_exception(exception_name)
                if not errors.lookup_error(exception_name):
                    errors.add_error(exception_name, exception_type)
    return errors


_schema = load_schema()
errors = _build_exceptions(_schema)
# A hack to make "from landscape_api.base.errors import UnknownComputer" to
# work:
sys.modules[__name__ + ".errors"] = errors


class MultiError(APIError):
    """
    An exception that represents multiple sub-exceptions.

    @ivar errors: A list of instances of L{APIError} or its subclasses.
    """

    def __init__(self, http_code, message):
        # Subclass from APIError just for convenience in catching; we're not
        # using its functionality
        APIError.__init__(self, http_code, message)
        self.errors = []
        for sub_error in self.message_data["errors"]:
            if sub_error.get("error") is not None:
                error_class = errors.lookup_error(
                    _get_error_code_name(sub_error["error"])
                )
                if error_class:
                    exception = error_class(self.code, message_data=sub_error)
                else:
                    exception = APIError(self.code, message_data=sub_error)
            else:
                exception = APIError(self.code, message_data=sub_error)
            self.errors.append(exception)

    def __str__(self):
        return "<%s errors=%s>" % (type(self).__name__, self.errors)


class UnauthorisedError(APIError):
    pass


class SignatureDoesNotMatchError(APIError):
    pass


class AuthFailureError(APIError):
    pass


class InvalidCredentialsError(APIError):
    pass


errors.add_error("MultiError", MultiError)
errors.add_error("Unauthorised", UnauthorisedError)
errors.add_error("SignatureDoesNotMatchError", SignatureDoesNotMatchError)
errors.add_error("AuthFailureError", AuthFailureError)
errors.add_error("InvalidCredentialsError", InvalidCredentialsError)


class _API(object):
    """Provide an object-oriented interface to the Landscape API.

    @param uri: The URI endpoint of the API.
    @param access_key: The 20 characters access key.
    @param secret_key: The 40 characters secret key.
    @param ssl_ca_file: Path to an alterneative CA certificate file.
    @param json: Return plain JSON response instead of a python object.
    @param schema: The schema data to use. If none is specified, it will be
        read from 'schemas.json' in the same directory as this module.

    Usage::

        api = API("https://landscape.canonical.com/api", "access_key",
                  "secret_key")
        computers = api.get_computers()
    """

    # TODO: accept an api_version parameter, use it instead of LATEST_VERSION

    _run_query = staticmethod(run_query)

    #     'overridden_apis' contains information about command-line API actions
    # that we want to override to (locally) take different arguments and invoke
    # a hand-coded method. This is used for situations where we want to provide
    # some extra layer of convenience to the user of this module or the command
    # line, like accepting a filename containing large data instead of
    # requiring it to be passed as a string.
    #     Any documentation that isn't specified in overridden_apis will be
    # looked up in the original schema.
    #     Right now it only supports replacing arguments one-for-one, but it
    # could be extended if we need to.
    overridden_apis = {}  # type: ignore

    def __init__(
        self, uri, access_key, secret_key, ssl_ca_file=None, json=False, schema=None
    ):
        self._uri = uri
        self._access_key = access_key
        self._secret_key = secret_key
        self._ssl_ca_file = ssl_ca_file
        self._json = json
        self._schema = schema if schema is not None else _schema

    def run_query(self, action_name, arguments):
        """
        Make a low-level query against the Landscape API, using details
        provided in the L{API} constructor.
        """

        result = self._run_query(
            self._access_key,
            self._secret_key,
            str(action_name),
            arguments,
            self._uri,
            self._ssl_ca_file,
        )
        if not self._json:
            result = json.loads(result)
        return result

    def call(self, method, **kwargs):
        """
        Invoke an API method, automatically encoding the arguments as defined
        in the schema.
        """

        action = self._schema[method][self.version]
        parameters = action["parameters"]
        fields = [(x["name"], x) for x in parameters]
        arguments = self._encode_struct_fields(fields, kwargs)
        return self.run_query(method, arguments)

    def _encode_struct_fields(self, fields, arguments, prefix=""):
        """
        Encode multiple named fields. This is used for both base argument
        processing and struct fields.

        @param fields: An associative list of field names to field parameter
            descriptions.
        @param arguments: A mapping of field names to actual values to encode.
        @param prefix: The prefix to put on all named parameters encoded.
        """

        result = {}
        for parameter_name, parameter_description in fields:
            # Figure out the type of the parameter and how to encode it.
            if parameter_name not in arguments:
                if not parameter_description.get("optional"):
                    raise TypeError("Missing parameter %s" % (parameter_name,))
            else:
                value = arguments.pop(parameter_name)
                encoded_item = self._encode_argument(
                    parameter_description, prefix + parameter_name, value
                )
                result.update(encoded_item)
        if arguments:
            raise TypeError("Extra arguments: %r" % (arguments,))
        return result

    def _encode_argument(self, parameter, name, value):
        """
        Encode a piece of data based on a parameter description.

        Returns a dictionary of parameters that should be included in the
        request.
        """

        if parameter.get("optional") and value == parameter.get("default"):
            return {}
        kind = parameter["type"].replace(" ", "_")
        handler = getattr(self, "_encode_%s" % (kind,))
        return handler(parameter, str(name), value)

    def _encode_integer(self, parameter, name, arg):
        return {name: str(arg)}

    def _encode_float(self, parameter, name, arg):
        return {name: str(arg)}

    def _encode_raw_string(self, parameter, name, value):
        return {name: str(value)}

    def _encode_enum(self, parameter, name, value):
        return {name: str(value)}

    def _encode_unicode(self, parameter, name, value):
        """
        Encode a python unicode object OR, for historical reasons, a datetime
        object, into an HTTP argument.
        """

        if isinstance(value, (datetime, date)):
            # This is really dumb compatibility stuff for APIs that aren't
            # properly specifying their type.
            return self._encode_date(parameter, name, value)
        return {name: str(value)}

    # These are Unicode types with specific validation.
    _encode_unicode_line = _encode_unicode
    _encode_unicode_title = _encode_unicode

    def _encode_file(self, parameter, name, value):
        contents = None
        with open(value, "rb") as the_file:
            contents = the_file.read()
        encoded_contents = b64encode(contents).decode("utf-8")
        # We send the filename along with the contents of the file.close
        filename = os.path.basename(value)
        payload = filename + "$$" + encoded_contents
        return {name: str(payload)}

    def _encode_boolean(self, parameter, name, value):
        return {name: "true" if value else "false"}

    def _encode_date(self, parameter, name, value):
        if isinstance(value, str):
            # allow people to pass strings, since the server has really good
            # date parsing and can handle lots of different formats.
            return {name: str(value)}
        return {name: str(value.strftime("%Y-%m-%dT%H:%M:%SZ"))}

    def _encode_list(self, parameter, name, sequence):
        """
        Encode a python list OR a comma-separated string into individual
        "foo.N" arguments.
        """

        result = {}
        if isinstance(sequence, str):
            sequence = [item.strip() for item in sequence.split(",")]
        for i, item in enumerate(sequence):
            encoded_item = self._encode_argument(
                parameter["item"], "%s.%s" % (name, i + 1), item
            )
            result.update(encoded_item)
        return result

    def _encode_mapping(self, parameter, name, items):
        """Encode a mapping into individual "foo.KEY=VALUE" arguments.

        Mappings andcomma-separated strings of KEY=VALUE pairs are
        supported.
        """

        if isinstance(items, str):
            items = {k.strip(): v.strip() for k, v in _parse_csv_mapping_safely(items)}
        elif hasattr(items, "items"):
            items = list(items.items())

        keyparam = parameter["key"]
        valueparam = parameter["value"]
        result = {}
        for key, value in items:
            key = self._encode_argument(keyparam, "<key>", key)["<key>"]
            subname = "{}.{}".format(name, key)
            result.update(self._encode_argument(valueparam, subname, value))
        return result

    def _encode_data(self, parameter, name, value):
        contents = None
        with open(value, "rb") as the_file:
            contents = the_file.read()
        encoded_contents = b64encode(contents)
        return {name: encoded_contents}

    def _encode_structure(self, parameter, name, dictionary):
        return self._encode_struct_fields(
            iter(list(parameter["fields"].items())),
            dictionary.copy(),
            prefix=name + ".",
        )

    def call_arbitrary(self, method, arguments):
        """
        Invoke an API method in a raw form, without encoding any parameters.

        @returns: The result as returned by the API method. If the C{json}
            parameter to L{API} was passed as C{True}, then the raw result will
            be returned. Otherwise it will be decoded as json and returned as a
            Python object.
        """

        return self.run_query(method, arguments)


def api_factory(schema, version=LATEST_VERSION):
    """
    A creator of L{API} classes. It will read a schema and create the methods
    on an L{API} to be available statically.
    """

    def _get_action_callers():
        """
        Build callable methods for all actions published through the schema
        that will invoke L{API.call}.
        """

        actions = {}
        for action_name in schema:
            action = schema[action_name].get(version)
            if action is None:
                # This API version doesn't support this action
                continue
            python_action_name = _lowercase_api_name(action_name)
            caller = _make_api_caller(action_name, action)
            actions[python_action_name] = caller
        return actions

    def _make_api_caller(action_name, action):
        method_name = _lowercase_api_name(action_name)
        positional_parameters = []
        optional_parameters = []
        defaults = []
        for parameter in action["parameters"]:
            if parameter.get("optional"):
                optional_parameters.append(parameter["name"])
                defaults.append(parameter["default"])
            else:
                positional_parameters.append(parameter["name"])

        positional_parameters.extend(optional_parameters)

        caller = _change_function(
            _caller,
            str(method_name),
            positional_parameters,
            defaults,
            action_name,
        )
        caller.__doc__ = _generate_doc(action)
        return caller

    def _generate_doc(action):
        """
        Generate a python docstring vaguely using pydoc syntax.
        """

        doc = inspect.cleandoc(action["doc"]) + "\n"
        for parameter in action["parameters"]:
            pdoc = parameter.get("doc", "Undocumented")
            param_doc = "@param %s: %s" % (parameter["name"], pdoc)
            doc += "\n" + textwrap.fill(param_doc, subsequent_indent="    ")
            doc += "\n@type %s: %s" % (parameter["name"], _describe_type(parameter))
        return doc

    def _describe_type(parameter):
        type_doc = parameter["type"]
        if type_doc == "list":
            type_doc += " (of %s)" % (_describe_type(parameter["item"]),)
        return type_doc

    def _change_function(func, newname, positional_parameters, defaults, action_name):
        """
        Return a new function with the provided name C{newname}, and changing
        the signature corresponding to C{positional_parameters} and
        C{defaults}.
        """

        argcount = len(positional_parameters) + 1
        code = func.__code__
        params = positional_parameters[:]
        params.insert(0, "self")
        varnames = [str(param) for param in params]
        # See _caller for the defined variable _args
        varnames.append("_args")
        varnames = tuple(varnames)
        co_nlocals = len(varnames)
        func_defaults = tuple(defaults) if defaults else None

        try:
            newcode = code.replace(
                co_argcount=argcount,
                co_nlocals=co_nlocals,
                co_name=str(newname),
                co_varnames=varnames,
            )
        except Exception:
            newcode = types.CodeType(
                argcount,
                code.co_kwonlyargcount,
                co_nlocals,
                code.co_stacksize,
                code.co_flags,
                code.co_code,
                code.co_consts,
                code.co_names,
                varnames,
                code.co_filename,
                str(newname),
                code.co_firstlineno,
                code.co_lnotab,
                code.co_freevars,
                code.co_cellvars,
            )

        # Make locals and action_name available to the method
        func_globals = func.__globals__.copy()
        func_globals["action_name"] = action_name
        return types.FunctionType(
            newcode, func_globals, str(newname), func_defaults, func.__closure__
        )

    def _caller(self):
        """Wrapper calling C{API.call} with the proper action name."""

        # TODO: Improve this
        global action_name
        # The locals of this function aren't obvious, because _change_function
        # modifies the parameters, and we have to access them with locals().
        _args = locals().copy()
        _args.pop("self")
        return self.call(action_name, **_args)  # noqa

    api_class = type("API", (_API,), {})
    api_class.version = version
    actions = _get_action_callers()
    for k, v in list(actions.items()):
        if not getattr(api_class, k, None):
            setattr(api_class, k, v)
        else:
            raise RuntimeError(
                "Tried setting '%s' from schema but that "
                "method already exists" % (k,)
            )

    return api_class


class API(api_factory(_schema)):  # type: ignore

    overridden_apis = {
        "ImportGPGKey": {
            "method": "import_gpg_key_from_file",
            "doc": None,
            "replace_args": {
                "material": {
                    "name": "filename",
                    "type": "unicode",
                    "doc": "The filename of the GPG file.",
                }
            },
        }
    }

    extra_actions = [
        _Action(
            "ssh",
            "ssh",
            "Try to ssh to a landscape computer",
            [
                {
                    "name": "query",
                    "type": "unicode",
                    "doc": "A query string which should return " "one computer",
                }
            ],
            [
                {
                    "name": "user",
                    "type": "unicode",
                    "default": None,
                    "doc": "If specified, the user to pass to " "the ssh command",
                }
            ],
        )
    ]

    def import_gpg_key_from_file(self, name, filename):
        """
        Import a GPG key with contents from the given filename.
        """

        with open(filename, "rt") as _file:
            material = _file.read()

        return self.call("ImportGPGKey", name=name, material=material)

    def ssh(self, query, user=None):
        """
        Calls C{get_computers}, and then the ssh command with the given result.
        """

        data = self.get_computers(query, with_network=True)
        if len(data) != 1:
            raise ValueError("Expected one computer as result, got %d" % len(data))
        computer = data[0]
        if not computer.get("network_devices", []):
            raise ValueError("Couldn't find a network device")
        address = computer["network_devices"][0]["ip_address"]
        args = ["ssh"]
        if user is not None:
            args.extend(["-l", user])
        args.append(address)
        os.execvp("ssh", args)


class APIv2(api_factory(_schema, version=FUTURE_VERSION)):  # type: ignore
    """Development version of the API."""

    _run_query = staticmethod(partial(run_query, version=FUTURE_VERSION))


class ParseActionsError(Exception):
    """Raises for errors parsing the API class"""


class UsageError(Exception):
    """Raises when help should be printed."""

    def __init__(self, stdout=None, stderr=None, error_code=None):
        Exception.__init__(self, "", stdout, stderr)
        self.stdout = stdout
        self.stderr = stderr
        self.error_code = error_code


class SchemaParameterAction(argparse.Action):
    """
    An L{argparse.Action} that knows how to parse command-line schema
    parameters and convert them to Python objects.
    """

    def __init__(self, *args, **kwargs):
        self.schema_parameter = kwargs.pop("schema_parameter")
        argparse.Action.__init__(self, *args, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        value = self.parse_argument(self.schema_parameter, values)
        setattr(namespace, self.dest, value)

    def parse_argument(self, parameter, value):
        suffix = parameter["type"].replace(" ", "_")
        parser = getattr(self, "parse_%s" % (suffix,))
        try:
            return parser(parameter, value)
        except UsageError:
            raise
        except:  # noqa
            raise UsageError(
                stderr="Couldn't parse value %r as %s\n" % (value, parameter["type"]),
                error_code=1,
            )

    def parse_integer(self, parameter, value):
        return int(value)

    def parse_float(self, parameter, value):
        return float(value)

    def parse_raw_string(self, parameter, value):
        return value

    def parse_enum(self, parameter, value):
        return value

    def parse_unicode(self, parameter, value):
        return value

    # These are Unicode types with specific validation.
    parse_unicode_line = parse_unicode
    parse_unicode_title = parse_unicode

    def parse_file(self, parameter, value):
        return str(value)

    def parse_date(self, parameter, value):
        # the server already has a good date parser, and to parse it well
        # ourselves we'd have to depend on the "dateutil" package...
        return value

    def parse_boolean(self, parameter, value):
        # This is only used for required arguments
        return value == "true"

    def parse_list(self, parameter, value):
        """Parse a comma-separated list of values converting it to a C{list}.

        Items can contain escaped commas as "\\," and they will be unescaped
        by this method.
        """

        items = _parse_csv_list_safely(value)
        return [
            self.parse_argument(parameter["item"], list_item)
            # TODO: check if list(...) should be used
            # list(self.parse_argument(parameter["item"], list_item))
            for list_item in items
            if list_item != ""
        ]

    def parse_mapping(self, parameter, value):
        """Parse a comma-separated list of key/value pairs into a dict.

        Keys and values are separated by "=".
        """

        keyparam = parameter["key"]
        valueparam = parameter["value"]
        result = {}
        for key, value in _parse_csv_mapping_safely(value):
            key = self.parse_argument(keyparam, key)
            value = self.parse_argument(valueparam, value)
            result[key] = value
        return result

    # TODO: Verify
    def parse_data(self, parameter, value):
        return value.decode("utf-8")


def _parse_csv_list_safely(value):
    """Yield each substring separated by commas.

    Substrings can contain escaped commas as "\\," and they will be
    unescaped by this function.
    """

    item = ""
    escaped = False
    for c in value:
        if c == ",":
            if escaped:
                item += c
                escaped = False
            else:
                yield item
                item = ""
        elif c == "\\":
            escaped = True
        else:
            if escaped:
                item += "\\"
            item += c
    if escaped:
        item += "\\"
    if item:
        yield item


def _parse_csv_mapping_safely(value):
    """Yield each key/value pair separated by commas.

    Substrings can contain escaped commas as "\\," and they will be
    unescaped by this function.
    """

    for item in _parse_csv_list_safely(value):
        key, sep, value = item.partition("=")
        if not sep:
            raise ValueError("invalid key/value pair {}".format(item))
        yield (key, value)


class CommandLine(object):
    """
    Implementation of the command-line logic.
    """

    # TODO: Accept an --api-version parameter.

    def __init__(self, stdout, stderr, exit, environ):
        self.stdout = stdout
        self.stderr = stderr
        self.exit = exit
        self.environ = environ

    def main(self, argv, schema):  # noqa
        """
        @param argv: The list of command line arguments, usually from
            C{sys.argv}.
        """

        version = self.environ.get("LANDSCAPE_API_VERSION", LATEST_VERSION)
        actions = self.get_actions(schema, version)

        try:
            # Build main parser
            parser = self.get_main_parser()

            # Special case for empty command line
            if len(argv) == 0:
                raise UsageError(
                    stdout=self.format_main_usage(parser, actions), error_code=0
                )

            action_map = dict([(action.name, action) for action in actions])

            (args, argv) = self.wrap_parse_args(parser.parse_known_args, argv)

            print_help_only = False
            if (args.action == "help" and len(argv) == 0) or (
                args.help and not args.action
            ):
                raise UsageError(
                    stdout=self.format_main_usage(parser, actions), error_code=0
                )
            if args.action == "help":
                print_help_only = True
                args.action = argv[0]
            if args.help:
                print_help_only = True

            if args.action != "call" and args.action not in action_map:
                if args.action is None:
                    raise UsageError(stderr="Please specify an action.\n")
                raise UsageError(stderr="Unknown action: %s\n" % args.action)

            if args.action == "call":
                action_parser = self.get_call_parser(parser)
            else:
                action = action_map[args.action]
                action_parser = self.get_action_parser(parser, action)

            if print_help_only:
                raise UsageError(stdout=action_parser.format_help(), error_code=0)

            api = self.get_api(args, schema, version)
            action_args = self.wrap_parse_args(action_parser.parse_args, argv)
            try:
                if args.action != "call":
                    result = self.call_known_action(
                        api, action, action_parser, action_args
                    )
                else:
                    result = self.call_arbitrary_action(api, action_args)
            except HTTPError as e:
                if e.error_code is not None:
                    self.stderr.write("\nGot server error:\nStatus: %s\n" % (e.code,))
                    self._format_api_error(e)
                else:
                    self.stderr.write(
                        "\nGot unexpected server error:\nStatus: %d\n" % e.code
                    )
                    self.stderr.write("Error message: %s\n" % e.message)
                return self.exit(2)

        except UsageError as e:
            if e.stdout is not None:
                self.stdout.write(e.stdout)
            if e.stderr is not None:
                self.stderr.write(e.stderr)
            if e.error_code is not None:
                return self.exit(e.error_code)
            else:
                return self.exit(1)
        except Exception as e:
            self.stderr.write(str(e) + "\n")
            return self.exit(1)

        if args.json_output or action.name in RAW_ACTIONS_LIST:
            # Some of the methods require raw output, for instance the code
            # part of scripts.
            self.stdout.write(str(result) + "\n")
        else:
            pprint(result, stream=self.stdout)

    def _format_api_error(self, error):
        """
        Format and print an HTTP error in a nice way.
        """

        message = error.error_message
        error_code = error.error_code
        if isinstance(message, str):
            message = message.encode("utf-8")
        if isinstance(error_code, str):
            error_code = error_code.encode("utf-8")
        self.stderr.write("Error code: %s\nError message: %s\n" % (error_code, message))

        if isinstance(error, MultiError):
            for error in error.errors:
                self._format_api_error(error)

    def call_known_action(self, api, action, action_parser, args):
        """
        Call a known, supported API action, using methods on L{API}.
        """

        positional_args = []
        keyword_args = {}
        for req_arg in action.required_args:
            # Special case to allow query to be multiple
            # space-separated tokens without having to be quoted on the
            # command line.
            argname = req_arg["name"].replace("_", "-")
            value = (
                " ".join(args.query) if argname == "query" else getattr(args, argname)
            )
            positional_args.append(value)
        for opt_arg in action.optional_args:
            opt_arg_name = opt_arg["name"].replace("_", "-")
            opt_arg_parameter_name = opt_arg["name"]
            arg = getattr(args, opt_arg_name, None)
            if arg is not None and arg != action_parser.get_default(opt_arg_name):
                keyword_args[opt_arg_parameter_name] = arg
        handler = getattr(api, action.method_name)
        return handler(*positional_args, **keyword_args)

    def call_arbitrary_action(self, api, args):
        """
        Call an arbitrary action specified as raw HTTP arguments, using
        L{API.call_arbitrary}.
        """

        action_name = args.action_name
        arguments = {}
        for arg in args.argument:
            key, value = arg.split("=", 1)
            arguments[key] = value
        return api.call_arbitrary(action_name, arguments)

    def get_api(self, args, schema, version):
        """
        Get an L{API} instance with parameters based on command line arguments
        or environment variables.
        """

        if args.key is not None:
            access_key = args.key
        elif "LANDSCAPE_API_KEY" in self.environ:
            access_key = self.environ["LANDSCAPE_API_KEY"]
        else:
            raise UsageError(stderr="Access key not specified.\n")

        if args.secret is not None:
            secret_key = args.secret
        elif "LANDSCAPE_API_SECRET" in self.environ:
            secret_key = self.environ["LANDSCAPE_API_SECRET"]
        else:
            raise UsageError(stderr="Secret key not specified.\n")

        if args.uri is not None:
            uri = args.uri
        elif "LANDSCAPE_API_URI" in self.environ:
            uri = self.environ["LANDSCAPE_API_URI"]
        else:
            raise UsageError(stderr="URI not specified.\n")

        if args.ssl_ca_file is not None:
            ssl_ca_file = args.ssl_ca_file
        else:
            ssl_ca_file = self.environ.get("LANDSCAPE_API_SSL_CA_FILE")

        api_class = APIv2 if version == FUTURE_VERSION else API
        if schema is not _schema:
            api_class = api_factory(schema, version=version)

        return api_class(
            uri, access_key, secret_key, ssl_ca_file, args.json_output, schema=schema
        )

    def get_action_parser(self, parser, action):
        """
        Build an L{argparse.ArgumentParser} for a particular action.
        """

        action_parser = argparse.ArgumentParser(
            add_help=False,
            description=action.doc,
            prog="%s %s" % (parser.prog, action.name),
        )
        for req_arg in action.required_args:
            argname = req_arg["name"].replace("_", "-")
            argdoc = self.get_parameter_doc(req_arg)
            if argname == "query":
                # Special case to allow query to be multiple space-separated
                # tokens without having to be quoted on the command line.
                action_parser.add_argument(argname, help=argdoc, nargs="+")
            else:
                action_parser.add_argument(
                    argname,
                    help=argdoc,
                    action=SchemaParameterAction,
                    schema_parameter=req_arg,
                )
        for opt_arg in action.optional_args:
            argname = opt_arg["name"].replace("_", "-")
            argdoc = self.get_parameter_doc(opt_arg)
            if opt_arg["default"] is False:
                action_parser.add_argument(
                    "--%s" % argname, dest=argname, action="store_true", help=argdoc
                )
            elif opt_arg["default"] is True:
                action_parser.add_argument(
                    "--no-%s" % argname, dest=argname, action="store_false", help=argdoc
                )
            else:
                action_parser.add_argument(
                    "--%s" % argname,
                    dest=argname,
                    help=argdoc,
                    action=SchemaParameterAction,
                    schema_parameter=opt_arg,
                )
        return action_parser

    def get_call_parser(self, parser):
        """
        Build the L{argparse.ArgumentParser} that knows how to handle the
        "call" action.
        """

        call_parser = argparse.ArgumentParser(
            add_help=False,
            description="Call an arbitrary Landscape API action.",
            prog="%s call" % (parser.prog,),
        )
        call_parser.add_argument(
            "action_name", help="The name of the Landscape API action."
        )
        call_parser.add_argument(
            "argument", help="An argument in key=value format", nargs="*"
        )
        return call_parser

    def get_main_parser(self):
        """
        Build the L{argparse.ArgumentParser} for the toplevel command line
        options.
        """

        # Not using argparse subgroups here because the help output gets very
        # messy when you have many subgroups.
        prog = sys.argv[0]
        parser = argparse.ArgumentParser(prog=prog, add_help=False)
        group = parser.add_argument_group("Global Arguments")
        group.add_argument(
            "-h",
            "--help",
            help="show this help message and exit",
            action="store_true",
            default=None,
        )
        group.add_argument(
            "--key",
            help="The Landscape access key to use when making "
            "the API request.  It defaults to the "
            "environment variable LANDSCAPE_API_KEY if "
            "not provided.",
        )
        group.add_argument(
            "--secret",
            help="The Landscape secret key to use when making "
            "the API request.  It defaults to the "
            "environment variable LANDSCAPE_API_SECRET if "
            "not provided.",
        )
        group.add_argument(
            "--uri",
            help="The URI of your Landscape endpoint. It "
            "defaults to the environment variable "
            "LANDSCAPE_API_URI if not provided.",
        )
        group.add_argument(
            "--json",
            dest="json_output",
            action="store_true",
            default=False,
            help="Output directly the JSON structure instead "
            "of the Python representation.",
        )
        group.add_argument(
            "--ssl-ca-file",
            help="SSL CA certificate to validate server.  If "
            "not provided, the SSL certificate provided "
            "by the server will be verified with the "
            "system CAs. It defaults to the environment "
            "variable LANDSCAPE_API_SSL_CA_FILE if not "
            "provided",
        )
        group = parser.add_argument_group("Actions")
        group.add_argument("action", default=None, nargs="?")
        return parser

    def wrap_parse_args(self, parse_args, *args, **kwargs):
        """
        Wraps a call to argparse's parse_args and captures all stdout, stderr,
        and sys.exits() and converts them into a UsageError.

        @param parse_args: The C{parse_args} method of an C{ArgumentParser} to
            execute.
        @param args: Positional args for the C{parse_args} call.
        @param kwargs: Keyword args for the C{parse_args} call.
        """

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = StringIO()
        sys.stderr = StringIO()

        try:
            try:
                return parse_args(*args, **kwargs)
            except SystemExit as e:
                code = e.code
                stdout = sys.stdout.getvalue()
                stderr = sys.stderr.getvalue()
                raise UsageError(stdout, stderr, code)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    def format_main_usage(self, parser, actions):
        """
        Format a help display for the command line

        @param parser: The main argparse object for the program.
        @param actions: The actions available.
        @returns: A formatted help string.
        """

        prog = parser.prog
        # Use argparse's help except the last line
        parser_help = parser.format_help()
        parser_help = "\n".join(parser_help.splitlines()[:-1])
        # Build help text
        help_lines = [
            "Landscape API client (Python 3) - version " ,
            parser_help,
        ]
        # Add action docs
        for action in actions:
            help_lines.append("  %s" % action.name)
        help_lines.append(
            "\nType '%(prog)s help ACTION' for help on a specific action.\n"
            % {"prog": prog}
        )
        return "\n".join(help_lines)

    def get_parameter_doc(self, parameter):
        doc = parameter["doc"]
        suffixes = {
            "list": "(comma-delimited list)",
            "mapping": "(comma-delimited KEY=VALUE pairs)",
            "boolean": "(true or false)",
            "date": "(time in YYYY-MM-DDTHH:MM:SS format)",
            "file": "filename",
        }
        suffix = suffixes.get(parameter["type"])
        if suffix:
            doc += " %s" % (suffix,)
        return doc

    def get_actions(self, schema, version):
        """
        Return a list of data structures representing callable actions provided
        by the API, based on the schema.

        @param schema: The schema, as returned from L{load_schema}.
        @param version: The API version to use.
        """

        overridden_apis = API.overridden_apis
        actions = []
        for name, version_handlers in list(schema.items()):
            if name in overridden_apis:
                # Don't add the base schema if it's been overridden; we don't
                # want duplicate actions.
                continue
            schema_action = version_handlers.get(version)
            if schema_action is None:
                # This action is not supported by this API version
                continue
            actions.append(self._get_action_from_schema(name, schema_action))

        for action_name, override_data in list(overridden_apis.items()):
            if action_name not in schema:
                # We ignore overridden APIs that aren't in the schema because
                # tests override the schema without necessarily providing all
                # the APIs that we override by default.
                continue
            overridden_schema = copy.deepcopy(schema[action_name][version])
            for parameter in overridden_schema["parameters"]:
                if parameter["name"] in override_data["replace_args"]:
                    replacement = override_data["replace_args"][parameter["name"]]
                    parameter.clear()
                    parameter.update(replacement)
            overridden_doc = override_data.get("doc")
            if overridden_doc:
                overridden_schema["doc"] = overridden_doc

            actions.append(
                self._get_action_from_schema(
                    action_name,
                    overridden_schema,
                    overridden_method_name=override_data["method"],
                )
            )

        actions.extend(API.extra_actions)

        return sorted(actions)

    def _get_action_from_schema(self, name, schema_action, overridden_method_name=None):
        """
        Get an L{_Action} instance representing the API action from the schema.
        """

        method_name = _lowercase_api_name(name)
        cli_name = schema_action.get("cli_name")
        cmdline_name = method_name.replace("_", "-") if cli_name is None else cli_name
        action_doc = schema_action["doc"]
        req_args = [
            parameter
            for parameter in schema_action["parameters"]
            if not parameter.get("optional")
        ]
        opt_args = [
            parameter
            for parameter in schema_action["parameters"]
            if parameter.get("optional")
        ]
        if overridden_method_name:
            method_name = overridden_method_name
        return _Action(cmdline_name, method_name, action_doc, req_args, opt_args)


def main(argv, stdout, stderr, exit, environ, schema=_schema):
    return CommandLine(stdout, stderr, exit, environ).main(argv, schema)


if __name__ == "__main__":
    main(sys.argv[1:], sys.stdout, sys.stderr, sys.exit, os.environ)