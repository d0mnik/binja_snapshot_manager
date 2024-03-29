from binaryninja import core_ui_enabled

if core_ui_enabled:
    from binaryninjaui import Sidebar
    from .snapshot_manager_widget import SnapshotManagerWidgetType

    Sidebar.addSidebarWidgetType(SnapshotManagerWidgetType())
