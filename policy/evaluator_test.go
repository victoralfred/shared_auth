package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvaluator_EvaluateCondition_Equals(t *testing.T) {
	evaluator := NewEvaluator()

	tests := []struct {
		name      string
		condition Condition
		context   map[string]interface{}
		expected  bool
	}{
		{
			name: "string equals - match",
			condition: Condition{
				Field:    "department",
				Operator: "eq",
				Value:    "sales",
			},
			context: map[string]interface{}{
				"department": "sales",
			},
			expected: true,
		},
		{
			name: "string equals - no match",
			condition: Condition{
				Field:    "department",
				Operator: "eq",
				Value:    "sales",
			},
			context: map[string]interface{}{
				"department": "marketing",
			},
			expected: false,
		},
		{
			name: "number equals - match",
			condition: Condition{
				Field:    "age",
				Operator: "eq",
				Value:    25,
			},
			context: map[string]interface{}{
				"age": 25,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(tt.condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_NotEquals(t *testing.T) {
	evaluator := NewEvaluator()

	condition := Condition{
		Field:    "status",
		Operator: "ne",
		Value:    "inactive",
	}

	tests := []struct {
		name     string
		context  map[string]interface{}
		expected bool
	}{
		{
			name: "not equals - true",
			context: map[string]interface{}{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "not equals - false",
			context: map[string]interface{}{
				"status": "inactive",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_GreaterThan(t *testing.T) {
	evaluator := NewEvaluator()

	tests := []struct {
		name      string
		condition Condition
		context   map[string]interface{}
		expected  bool
	}{
		{
			name: "greater than - int - true",
			condition: Condition{
				Field:    "age",
				Operator: "gt",
				Value:    18,
			},
			context: map[string]interface{}{
				"age": 25,
			},
			expected: true,
		},
		{
			name: "greater than - int - false",
			condition: Condition{
				Field:    "age",
				Operator: "gt",
				Value:    30,
			},
			context: map[string]interface{}{
				"age": 25,
			},
			expected: false,
		},
		{
			name: "greater than - float",
			condition: Condition{
				Field:    "price",
				Operator: "gt",
				Value:    99.99,
			},
			context: map[string]interface{}{
				"price": 149.99,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(tt.condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_LessThan(t *testing.T) {
	evaluator := NewEvaluator()

	condition := Condition{
		Field:    "quantity",
		Operator: "lt",
		Value:    10,
	}

	tests := []struct {
		name     string
		context  map[string]interface{}
		expected bool
	}{
		{
			name: "less than - true",
			context: map[string]interface{}{
				"quantity": 5,
			},
			expected: true,
		},
		{
			name: "less than - false",
			context: map[string]interface{}{
				"quantity": 15,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_In(t *testing.T) {
	evaluator := NewEvaluator()

	tests := []struct {
		name      string
		condition Condition
		context   map[string]interface{}
		expected  bool
	}{
		{
			name: "in list - true",
			condition: Condition{
				Field:    "status",
				Operator: "in",
				Value:    []interface{}{"pending", "processing", "approved"},
			},
			context: map[string]interface{}{
				"status": "pending",
			},
			expected: true,
		},
		{
			name: "in list - false",
			condition: Condition{
				Field:    "status",
				Operator: "in",
				Value:    []interface{}{"pending", "processing"},
			},
			context: map[string]interface{}{
				"status": "completed",
			},
			expected: false,
		},
		{
			name: "in number list",
			condition: Condition{
				Field:    "priority",
				Operator: "in",
				Value:    []interface{}{1, 2, 3},
			},
			context: map[string]interface{}{
				"priority": 2,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(tt.condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_NotIn(t *testing.T) {
	evaluator := NewEvaluator()

	condition := Condition{
		Field:    "department",
		Operator: "not_in",
		Value:    []interface{}{"hr", "legal"},
	}

	tests := []struct {
		name     string
		context  map[string]interface{}
		expected bool
	}{
		{
			name: "not in list - true",
			context: map[string]interface{}{
				"department": "sales",
			},
			expected: true,
		},
		{
			name: "not in list - false",
			context: map[string]interface{}{
				"department": "hr",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateCondition(condition, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateCondition_MissingField(t *testing.T) {
	evaluator := NewEvaluator()

	condition := Condition{
		Field:    "department",
		Operator: "eq",
		Value:    "sales",
	}

	// Context doesn't have the field
	context := map[string]interface{}{
		"other_field": "value",
	}

	result := evaluator.EvaluateCondition(condition, context)
	assert.False(t, result)
}

func TestEvaluator_EvaluateConditions_AND(t *testing.T) {
	evaluator := NewEvaluator()

	conditions := []Condition{
		{
			Field:    "department",
			Operator: "eq",
			Value:    "sales",
		},
		{
			Field:    "experience_years",
			Operator: "gt",
			Value:    5,
		},
		{
			Field:    "status",
			Operator: "eq",
			Value:    "active",
		},
	}

	tests := []struct {
		name     string
		context  map[string]interface{}
		expected bool
	}{
		{
			name: "all conditions match",
			context: map[string]interface{}{
				"department":       "sales",
				"experience_years": 7,
				"status":           "active",
			},
			expected: true,
		},
		{
			name: "one condition fails",
			context: map[string]interface{}{
				"department":       "sales",
				"experience_years": 3, // Fails
				"status":           "active",
			},
			expected: false,
		},
		{
			name: "all conditions fail",
			context: map[string]interface{}{
				"department":       "marketing",
				"experience_years": 2,
				"status":           "inactive",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateConditions(conditions, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluator_EvaluateConditions_Empty(t *testing.T) {
	evaluator := NewEvaluator()

	// Empty conditions should return true
	result := evaluator.EvaluateConditions([]Condition{}, map[string]interface{}{})
	assert.True(t, result)
}

func TestEvaluator_RealWorldScenario(t *testing.T) {
	evaluator := NewEvaluator()

	// Scenario: Approve expense if amount < 1000 OR (amount < 5000 AND approver_level >= 2)
	// This tests multiple conditions together

	tests := []struct {
		name       string
		conditions []Condition
		context    map[string]interface{}
		expected   bool
	}{
		{
			name: "small expense approved automatically",
			conditions: []Condition{
				{
					Field:    "amount",
					Operator: "lt",
					Value:    1000,
				},
			},
			context: map[string]interface{}{
				"amount": 500,
			},
			expected: true,
		},
		{
			name: "medium expense with high-level approver",
			conditions: []Condition{
				{
					Field:    "amount",
					Operator: "lt",
					Value:    5000,
				},
				{
					Field:    "approver_level",
					Operator: "gte",
					Value:    2,
				},
			},
			context: map[string]interface{}{
				"amount":         3000,
				"approver_level": 3,
			},
			expected: true,
		},
		{
			name: "medium expense with low-level approver - rejected",
			conditions: []Condition{
				{
					Field:    "amount",
					Operator: "lt",
					Value:    5000,
				},
				{
					Field:    "approver_level",
					Operator: "gte",
					Value:    2,
				},
			},
			context: map[string]interface{}{
				"amount":         3000,
				"approver_level": 1,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := evaluator.EvaluateConditions(tt.conditions, tt.context)
			assert.Equal(t, tt.expected, result)
		})
	}
}
