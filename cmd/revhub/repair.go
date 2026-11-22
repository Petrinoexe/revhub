package main

import (
	"flag"
	"log"

	"revhub/internal/install"
)

// cmdRepair чинит системную часть уже стоящей установки: юнит xray, правило
// sudo для применения конфига и сам конфиг ядра. Состояние, пароль и TLS не
// трогает — этим занимается install/обновление.
func cmdRepair(args []string) {
	fs := flag.NewFlagSet("repair", flag.ExitOnError)
	o := install.Defaults()
	statePath := fs.String("state", "", "файл состояния (по умолчанию <etc-dir>/state.json)")
	fs.StringVar(&o.Prefix, "prefix", o.Prefix, "каталог бинаря")
	fs.StringVar(&o.EtcDir, "etc-dir", o.EtcDir, "конфиги и состояние")
	fs.StringVar(&o.StateDir, "state-dir", o.StateDir, "артефакты узла")
	fs.StringVar(&o.UnitDir, "unit-dir", o.UnitDir, "куда класть systemd-юниты")
	fs.StringVar(&o.PanelUser, "panel-user", o.PanelUser, "системный пользователь панели")
	fs.BoolVar(&o.DryRun, "dry-run", false, "только показать, что будет сделано")
	asJSON := fs.Bool("json", false, "отдать отчёт в JSON")
	fs.Parse(args)

	if *statePath == "" {
		*statePath = o.EtcDir + "/state.json"
	}
	rep, err := install.Repair(o, *statePath)
	if err != nil {
		printReport(rep, *asJSON)
		log.Fatalf("починка остановлена: %v", err)
	}
	printReport(rep, *asJSON)
}
