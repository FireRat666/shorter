package main

import (
	_ "embed"
	"html/template"
	"os"
	"path/filepath"
)

//go:embed embedded/index.default.tmpl
var defaultIndexHTML string

//go:embed embedded/showLink.default.tmpl
var defaultShowLinkHTML string

//go:embed embedded/showText.default.tmpl
var defaultShowTextHTML string

//go:embed embedded/error.default.tmpl
var defaultErrorHTML string

//go:embed embedded/admin.default.tmpl
var defaultAdminHTML string

//go:embed embedded/admin_edit.default.tmpl
var defaultAdminEditHTML string

//go:embed embedded/admin_edit_static_link.default.tmpl
var defaultAdminEditStaticLinkHTML string

//go:embed embedded/admin_stats.default.tmpl
var defaultAdminStatsHTML string

//go:embed embedded/login.default.tmpl
var defaultLoginHTML string

//go:embed embedded/password_prompt.default.tmpl
var defaultPasswordPromptHTML string

// initTemplates initializes the template map, loading custom templates from disk
// and falling back to embedded templates if custom ones are not found.
func initTemplates() error {
	templateMap = make(map[string]*template.Template)

	loadTemplate("index", defaultIndexHTML)
	loadTemplate("showLink", defaultShowLinkHTML)
	loadTemplate("showText", defaultShowTextHTML)
	loadTemplate("admin", defaultAdminHTML)
	loadTemplate("admin_edit", defaultAdminEditHTML)
	loadTemplate("admin_edit_static_link", defaultAdminEditStaticLinkHTML)
	loadTemplate("error", defaultErrorHTML)
	loadTemplate("login", defaultLoginHTML)
	loadTemplate("password_prompt", defaultPasswordPromptHTML)
	loadTemplate("admin_stats", defaultAdminStatsHTML)

	slogger.Info("Successfully loaded HTML templates", "count", len(templateMap))
	return nil
}

// loadTemplate attempts to parse a template from a file on disk. If the file
// does not exist or fails to parse, it falls back to the provided default template string.
func loadTemplate(name, defaultContent string) {
	path := filepath.Join(config.BaseDir, "templates", name+".tmpl")
	tmpl, err := template.ParseFiles(path)
	if err != nil {
		tmpl = template.Must(template.New(name).Parse(defaultContent))
	}
	templateMap[name] = tmpl
}

// initImages discovers and loads all image assets from the configured directory into memory.
func initImages() error {
	ImageMap = make(map[string][]byte)
	imgDir := filepath.Join(config.BaseDir, "images")

	files, err := os.ReadDir(imgDir)
	if err != nil {
		// Images might be optional, so we can treat this as a warning.
		slogger.Warn("Image directory not found, no images will be served.", "path", imgDir, "error", err)
		return nil // Not a fatal error
	}

	for _, file := range files {
		if !file.IsDir() {
			filePath := filepath.Join(imgDir, file.Name())
			data, err := os.ReadFile(filePath)
			if err != nil {
				slogger.Warn("Failed to read image file, skipping.", "path", filePath, "error", err)
				continue
			}
			ImageMap[file.Name()] = data
		}
	}
	slogger.Info("Successfully loaded image assets", "count", len(ImageMap))
	return nil
}
