// Project Safe 0.4. Run in After Effects: File > Scripts > Run Script File.
// Reads the open project. Writes only the explicitly selected dependency list.
(function () {
    if (!app.project || !app.project.file) {
        alert("First save your After Effects project, then run this script again.");
        return;
    }
    function escapeXml(value) {
        return String(value).replace(/&/g, "&amp;").replace(/</g, "&lt;")
            .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
    }
    var lines = ['<?xml version="1.0" encoding="UTF-8"?>',
        '<ProjectSafeDependencies version="1" editor="After Effects">',
        '<project path="' + escapeXml(app.project.file.fsName) + '"/>'];
    var seen = {};
    function add(file, role) {
        if (!file) return;
        var key = "$" + file.fsName;
        if (seen[key]) return;
        seen[key] = true;
        lines.push('<file role="' + role + '" path="' + escapeXml(file.fsName) + '"/>');
    }
    for (var i = 1; i <= app.project.numItems; i++) {
        var item = app.project.item(i);
        if (!(item instanceof FootageItem)) continue;
        try {
            add(item.file, "footage");
            if (item.proxySource && item.proxySource.file) add(item.proxySource.file, "proxy");
            if (item.footageMissing) lines.push('<warning>Missing footage: ' + escapeXml(item.name) + '</warning>');
        } catch (error) {
            lines.push('<warning>Could not inspect footage: ' + escapeXml(item.name) + '</warning>');
        }
    }
    lines.push('<warning>Image sequences require Collect Files in After Effects. This list may contain only the first frame.</warning>');
    lines.push('<warning>Save the project and re-export this list after editing. Fonts, plugins and expression-loaded files need manual review.</warning>');
    lines.push('</ProjectSafeDependencies>');
    var output = new File(app.project.file.fsName + ".psdeps");
    output = output.saveDlg("Save dependency list next to the project", "*.psdeps");
    if (!output) return;
    if (!/.psdeps$/i.test(output.name)) output = new File(output.fsName + ".psdeps");
    if (output.exists && !confirm("Replace existing dependency list?")) return;
    // Refuse writing over the source project even if an extension was mistyped.
    if (output.fsName.toLowerCase() === app.project.file.fsName.toLowerCase()) {
        alert("Choose a different file. The source project will not be overwritten.");
        return;
    }
    output.encoding = "UTF-8";
    if (!output.open("w")) { alert("Cannot write dependency list."); return; }
    var ok = output.write(lines.join("\n"));
    output.close();
    alert(ok ? "Dependency list saved. Put it in your project folder and scan with Project Safe. The project was not changed." : "Could not finish writing dependency list.");
}());
