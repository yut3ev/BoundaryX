"""BoundaryX Dialogs Package.

Provides modal dialogs for project management, identity authoring, resource provisioning,
policy editing, and pre-flight test execution plans.
"""

from __future__ import annotations

from boundaryx.ui.dialogs.identity_dialog import IdentityDialog
from boundaryx.ui.dialogs.policy_dialog import PolicyDialog
from boundaryx.ui.dialogs.project_dialog import ProjectDialog
from boundaryx.ui.dialogs.resource_dialog import ResourceDialog
from boundaryx.ui.dialogs.test_preview_dialog import TestPreviewDialog

__all__ = [
    "IdentityDialog",
    "PolicyDialog",
    "ProjectDialog",
    "ResourceDialog",
    "TestPreviewDialog",
]
