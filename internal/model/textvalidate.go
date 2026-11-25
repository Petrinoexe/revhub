package model

import (
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

// validateConfigText не пускает переводы строк и другие управляющие символы
// в поля, из которых строятся shell-скрипты, wg-quick и dnsmasq конфиги.
// BootstrapLog — единственное поле State, где многострочный текст законен:
// это результат удалённой установки, а не вход генератора.
func validateConfigText(s State) error {
	return walkConfigText(reflect.ValueOf(s), "state", "")
}

func walkConfigText(v reflect.Value, path, fieldName string) error {
	if !v.IsValid() {
		return nil
	}
	if fieldName == "BootstrapLog" {
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return nil
		}
		return walkConfigText(v.Elem(), path, "")
	case reflect.String:
		if strings.ContainsFunc(v.String(), unicode.IsControl) {
			return fmt.Errorf("%s: управляющие символы запрещены", path)
		}
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			name := t.Field(i).Name
			if err := walkConfigText(v.Field(i), path+"."+name, name); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := walkConfigText(v.Index(i), fmt.Sprintf("%s[%d]", path, i), ""); err != nil {
				return err
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if err := walkConfigText(iter.Key(), path+"{key}", ""); err != nil {
				return err
			}
			if err := walkConfigText(iter.Value(), path+"{value}", ""); err != nil {
				return err
			}
		}
	}
	return nil
}
