package main

import (
	hplugin "github.com/hashicorp/go-plugin"

	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"

	"github.com/complytime/compliance-to-policy-plugins/opa-plugin/server"
)

func main() {
	conformaPlugin := server.NewPlugin()
	plugins := map[string]hplugin.Plugin{
		plugin.PVPPluginName: &plugin.PVPPlugin{Impl: conformaPlugin},
	}
	config := plugin.ServeConfig{
		PluginSet: plugins,
		Logger:    server.Logger(),
	}
	plugin.Register(config)
}
