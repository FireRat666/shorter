package main

import (
	_ "embed"
	"html/template"
	"os"
	"path/filepath"
)

//go:embed embedded/index.default.tmpl
var defaultIndexHTML string

//go:embed embedded/link_created.default.tmpl
var defaultLinkCreatedHTML string

//go:embed embedded/text_dump_created.default.tmpl
var defaultTextDumpCreatedHTML string

//go:embed embedded/show_redirect.default.tmpl
var defaultShowRedirectHTML string

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

//go:embed embedded/admin_edit_link.default.tmpl
var defaultAdminEditLinkHTML string

//go:embed embedded/admin_stats.default.tmpl
var defaultAdminStatsHTML string

//go:embed embedded/login.default.tmpl
var defaultLoginHTML string

//go:embed embedded/admin_api_keys.default.tmpl
var defaultAdminAPIKeysHTML string

//go:embed embedded/password_prompt.default.tmpl
var defaultPasswordPromptHTML string

//go:embed embedded/admin_stats_top_links.partial.tmpl
var defaultAdminStatsTopLinksPartialHTML string

//go:embed embedded/admin_stats_creator_stats.partial.tmpl
var defaultAdminStatsCreatorStatsPartialHTML string

//go:embed embedded/admin_stats_recent_activity.partial.tmpl
var defaultAdminStatsRecentActivityPartialHTML string

//go:embed embedded/admin_stats_overall.partial.tmpl
var defaultAdminStatsOverallPartialHTML string

//go:embed embedded/admin_stats_domain_list.partial.tmpl
var defaultAdminStatsDomainListPartialHTML string

//go:embed embedded/admin_stats_domain_details.partial.tmpl
var defaultAdminStatsDomainDetailsPartialHTML string

// initTemplates initializes the template map, loading custom templates from disk
// and falling back to embedded templates if custom ones are not found.
func initTemplates() error {
	templateMap = make(map[string]*template.Template)

	// Define a function map to add custom functions to templates.
	funcMap := template.FuncMap{
		"add": func(a, b int) int {
			return a + b
		},
	}

	loadTemplate("index", defaultIndexHTML, funcMap)
	loadTemplate("text_dump_created", defaultTextDumpCreatedHTML, funcMap)
	loadTemplate("link_created", defaultLinkCreatedHTML, funcMap)
	loadTemplate("show_redirect", defaultShowRedirectHTML, funcMap)
	loadTemplate("showText", defaultShowTextHTML, funcMap)
	loadTemplate("admin", defaultAdminHTML, funcMap)
	loadTemplate("admin_edit", defaultAdminEditHTML, funcMap)
	loadTemplate("admin_edit_static_link", defaultAdminEditStaticLinkHTML, funcMap)
	loadTemplate("admin_edit_link", defaultAdminEditLinkHTML, funcMap)
	loadTemplate("error", defaultErrorHTML, funcMap)
	loadTemplate("login", defaultLoginHTML, funcMap)
	loadTemplate("admin_api_keys", defaultAdminAPIKeysHTML, funcMap)
	loadTemplate("password_prompt", defaultPasswordPromptHTML, funcMap)
	loadTemplate("admin_stats", defaultAdminStatsHTML, funcMap)
	loadTemplate("admin_stats_top_links.partial", defaultAdminStatsTopLinksPartialHTML, funcMap)
	loadTemplate("admin_stats_overall.partial", defaultAdminStatsOverallPartialHTML, funcMap)
	loadTemplate("admin_stats_recent_activity.partial", defaultAdminStatsRecentActivityPartialHTML, funcMap)
	loadTemplate("admin_stats_domain_list.partial", defaultAdminStatsDomainListPartialHTML, funcMap)
	loadTemplate("admin_stats_domain_details.partial", defaultAdminStatsDomainDetailsPartialHTML, funcMap)
	loadTemplate("admin_stats_creator_stats.partial", defaultAdminStatsCreatorStatsPartialHTML, funcMap)

	slogger.Info("Successfully loaded HTML templates", "count", len(templateMap))
	return nil
}

// loadTemplate attempts to parse a template from a file on disk. If the file
// does not exist or fails to parse, it falls back to the provided default template string.
func loadTemplate(name, defaultContent string, funcMap template.FuncMap) {
	path := filepath.Join(config.BaseDir, "templates", name+".tmpl")
	// We must associate the funcs before parsing.
	tmpl, err := template.New(filepath.Base(path)).Funcs(funcMap).ParseFiles(path)
	if err != nil {
		tmpl = template.Must(template.New(name).Funcs(funcMap).Parse(defaultContent))
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
