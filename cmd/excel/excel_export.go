package excel

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ExportExcel excel导出
func (e *Excel) ExportExcel(sheet, title string, resMap map[string]interface{}, changeHead map[string]string) (err error) {
	index, _ := e.F.GetSheetIndex(sheet)
	if index < 0 { // 如果sheet名称不存在
		e.F.NewSheet(sheet)
	}

	var endColName string
	var dataRow int
	hasTitle := false
	for _, data := range resMap {
		// 构造excel表格
		// 取目标对象的元素类型、字段类型和 tag
		dataValue := reflect.ValueOf(data)
		// 判断数据的类型
		if dataValue.Kind() != reflect.Slice {
			return errors.New("invalid data type")
		}
		if !hasTitle {
			// 构造表头
			endColName, dataRow, err = normalBuildTitle(e, sheet, title, changeHead, dataValue)
			if err != nil {
				return err
			}
			hasTitle = true
		}
		// 构造数据行
		err = normalBuildDataRow(e, sheet, endColName, dataRow, dataValue)
		if err != nil {
			return err
		}
		// 0即默认第一列
		mergeColCell(e, sheet, 0, dataRow-1, dataValue.Len())
		dataRow += dataValue.Len()
	}
	return nil
}

// getExcelColumnName 根据列数生成 Excel 列名
func getExcelColumnName(columnNumber int) string {
	columnName := ""
	for columnNumber > 0 {
		remainder := (columnNumber - 1) % 26
		columnName = string(rune('A'+remainder)) + columnName
		columnNumber = (columnNumber - 1) / 26
	}
	return columnName
}

// 构造表头（endColName 最后一列的列名 dataRow 数据行开始的行号）
func normalBuildTitle(e *Excel, sheet, title string, changeHead map[string]string, dataValue reflect.Value) (endColName string, dataRow int, err error) {
	dataType := dataValue.Type().Elem() // 获取导入目标对象的类型信息
	var exportTitle []ExcelTag          // 遍历目标对象的字段
	for i := 0; i < dataType.NumField(); i++ {
		var excelTag ExcelTag
		field := dataType.Field(i) // 获取字段信息和tag
		tag := field.Tag.Get(ExcelTagKey)
		if tag == "" { // 如果非导出则跳过
			continue
		}

		err = excelTag.GetTag(tag)
		if err != nil {
			return
		}
		// 更改指定字段的表头标题
		if changeHead != nil && changeHead[field.Name] != "" {
			excelTag.Name = changeHead[field.Name]
		}
		exportTitle = append(exportTitle, excelTag)
	}
	// 排序
	sort.Slice(exportTitle, func(i, j int) bool {
		return exportTitle[i].Index < exportTitle[j].Index
	})
	var titleRowData []interface{} // 列头行
	for i, colTitle := range exportTitle {
		endColName := getExcelColumnName(i + 1)
		if colTitle.Width > 0 { // 根据给定的宽度设置列宽
			_ = e.F.SetColWidth(sheet, endColName, endColName, float64(colTitle.Width))
		} else {
			_ = e.F.SetColWidth(sheet, endColName, endColName, float64(20)) // 默认宽度为20
		}
		titleRowData = append(titleRowData, colTitle.Name)
	}
	endColName = getExcelColumnName(len(titleRowData)) // 根据列数生成 Excel 列名
	if title != "" {
		dataRow = 3 // 如果有title，那么从第3行开始就是数据行，第1行是title，第2行是表头
		e.F.SetCellValue(sheet, "A1", title)
		e.F.MergeCell(sheet, "A1", endColName+"1") // 合并标题单元格
		e.F.SetCellStyle(sheet, "A1", endColName+"1", e.TitleStyle)
		e.F.SetRowHeight(sheet, 1, float64(30)) // 第一行行高
		e.F.SetRowHeight(sheet, 2, float64(30)) // 第二行行高
		e.F.SetCellStyle(sheet, "A2", endColName+"2", e.HeadStyle)
		if err = e.F.SetSheetRow(sheet, "A2", &titleRowData); err != nil {
			return
		}
	} else {
		dataRow = 2 // 如果没有title，那么从第2行开始就是数据行，第1行是表头
		e.F.SetRowHeight(sheet, 1, float64(30))
		e.F.SetCellStyle(sheet, "A1", endColName+"1", e.HeadStyle)
		if err = e.F.SetSheetRow(sheet, "A1", &titleRowData); err != nil {
			return
		}
	}
	return
}

// 构造数据行
func normalBuildDataRow(e *Excel, sheet, endColName string, row int, dataValue reflect.Value) (err error) {
	//实时写入数据
	for i := 0; i < dataValue.Len(); i++ {
		startCol := fmt.Sprintf("A%d", row)
		endCol := fmt.Sprintf("%s%d", endColName, row)
		item := dataValue.Index(i)
		typ := item.Type()
		num := item.NumField()
		var exportRow []ExcelTag
		maxLen := 0 // 记录这一行中，数据最多的单元格的值的长度
		//遍历结构体的所有字段
		for j := 0; j < num; j++ {
			dataField := typ.Field(j) //获取到struct标签，需要通过reflect.Type来获取tag标签的值
			tagVal := dataField.Tag.Get(ExcelTagKey)
			if tagVal == "" { // 如果非导出则跳过
				continue
			}

			var dataCol ExcelTag
			err = dataCol.GetTag(tagVal)
			fieldData := item.FieldByName(dataField.Name) // 取字段值
			if fieldData.Type().String() == "string" {    // string类型的才计算长度
				rwsTemp := fieldData.Len() // 当前单元格内容的长度
				if rwsTemp > maxLen {      //这里取每一行中的每一列字符长度最大的那一列的字符
					maxLen = rwsTemp
				}
			}
			// 替换
			if dataCol.Replace != "" {
				split := strings.Split(dataCol.Replace, ",")
				for j := range split {
					s := strings.Split(split[j], "_") // 根据下划线进行分割，格式：需要替换的内容_替换后的内容
					value := fieldData.String()
					if strings.Contains(fieldData.Type().String(), "int") {
						value = strconv.Itoa(int(fieldData.Int()))
					} else if fieldData.Type().String() == "bool" {
						value = strconv.FormatBool(fieldData.Bool())
					} else if strings.Contains(fieldData.Type().String(), "float") {
						value = strconv.FormatFloat(fieldData.Float(), 'f', -1, 64)
					}
					if s[0] == value {
						dataCol.Value = s[1]
					}
				}
			} else {
				dataCol.Value = fieldData
			}
			if err != nil {
				return
			}
			exportRow = append(exportRow, dataCol)
		}
		// 排序
		sort.Slice(exportRow, func(i, j int) bool {
			return exportRow[i].Index < exportRow[j].Index
		})
		var rowData []interface{} // 数据列
		for _, colTitle := range exportRow {
			rowData = append(rowData, colTitle.Value)
		}
		if row%2 == 0 {
			_ = e.F.SetCellStyle(sheet, startCol, endCol, e.ContentStyle2)
		} else {
			_ = e.F.SetCellStyle(sheet, startCol, endCol, e.ContentStyle1)
		}
		if maxLen > 25 { // 自适应行高
			d := maxLen / 25
			f := 25 * d
			_ = e.F.SetRowHeight(sheet, row, float64(f))
		} else {
			_ = e.F.SetRowHeight(sheet, row, float64(25)) // 默认行高25
		}
		if err = e.F.SetSheetRow(sheet, startCol, &rowData); err != nil {
			return
		}
		row++
	}
	return
}

func mergeColCell(e *Excel, sheet string, colIdx, rowIdx, height int) error {
	if height == 1 {
		return nil
	}

	hCell, err := getCellIdx(colIdx, rowIdx)
	if err != nil {
		return err
	}

	vCell, err := getCellIdx(colIdx, rowIdx+height-1)
	if err != nil {
		return err
	}

	if err := e.F.MergeCell(sheet, hCell, vCell); err != nil {
		return err
	}

	return nil
}

const (
	rowStartIdx = 1
	colStartIdx = 1
)

func getCellIdx(col int, row int) (string, error) {
	// 由于第三方库的行和列不是从0开始，所以这里加上开始数，使调用者可以按照从0开始进行计数
	return excelize.CoordinatesToCellName(col+colStartIdx, row+rowStartIdx)
}
