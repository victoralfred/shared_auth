package policy

import (
	"reflect"
)

// Evaluator evaluates ABAC conditions
type Evaluator struct{}

// NewEvaluator creates a new condition evaluator
func NewEvaluator() *Evaluator {
	return &Evaluator{}
}

// EvaluateConditions evaluates all conditions (AND logic)
func (e *Evaluator) EvaluateConditions(conditions []Condition, context map[string]interface{}) bool {
	for _, condition := range conditions {
		if !e.EvaluateCondition(condition, context) {
			return false
		}
	}
	return true
}

// EvaluateCondition evaluates a single condition
func (e *Evaluator) EvaluateCondition(condition Condition, context map[string]interface{}) bool {
	// Get field value from context
	fieldValue, exists := context[condition.Field]
	if !exists {
		return false
	}

	// Evaluate based on operator
	switch condition.Operator {
	case "eq":
		return e.equals(fieldValue, condition.Value)
	case "ne":
		return !e.equals(fieldValue, condition.Value)
	case "gt":
		return e.greaterThan(fieldValue, condition.Value)
	case "lt":
		return e.lessThan(fieldValue, condition.Value)
	case "gte":
		return e.greaterThanOrEqual(fieldValue, condition.Value)
	case "lte":
		return e.lessThanOrEqual(fieldValue, condition.Value)
	case "in":
		return e.in(fieldValue, condition.Value)
	case "not_in":
		return !e.in(fieldValue, condition.Value)
	default:
		return false
	}
}

// equals checks equality
func (e *Evaluator) equals(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

// greaterThan checks if a > b
func (e *Evaluator) greaterThan(a, b interface{}) bool {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)

	if aOk && bOk {
		return aFloat > bFloat
	}
	return false
}

// lessThan checks if a < b
func (e *Evaluator) lessThan(a, b interface{}) bool {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)

	if aOk && bOk {
		return aFloat < bFloat
	}
	return false
}

// greaterThanOrEqual checks if a >= b
func (e *Evaluator) greaterThanOrEqual(a, b interface{}) bool {
	return e.greaterThan(a, b) || e.equals(a, b)
}

// lessThanOrEqual checks if a <= b
func (e *Evaluator) lessThanOrEqual(a, b interface{}) bool {
	return e.lessThan(a, b) || e.equals(a, b)
}

// in checks if value is in list
func (e *Evaluator) in(value, list interface{}) bool {
	listValue := reflect.ValueOf(list)

	if listValue.Kind() != reflect.Slice && listValue.Kind() != reflect.Array {
		return false
	}

	for i := 0; i < listValue.Len(); i++ {
		if e.equals(value, listValue.Index(i).Interface()) {
			return true
		}
	}

	return false
}

// toFloat64 converts interface to float64
func toFloat64(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}
