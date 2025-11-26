package main

import (
    "crypto/tls"
    "fmt"
    "testing"
    "time"

    corev2 "github.com/sensu/sensu-go/api/core/v2"
    "github.com/sensu/sensu-plugin-sdk/sensu"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
    "github.com/stretchr/testify/require"
)

type mockValidator struct {
    mock.Mock
}

func (m *mockValidator) Var(var interface{}, tag string) error {
    args := m.Called(var, tag)
    return args.Error(0)
}

type mockCheck struct {
    mock.Mock
}

func (m *mockCheck) Execute() {
    m.Called()
}

func TestCheckArgs_ValidationsPass_ReturnsOK(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = "example.com"
    plugin.Critical = 3
    plugin.Warning = 7

    validate = &mockValidator{}
    validate.On("Var", plugin.Host, "fqdn").Return(nil)

    state, err := checkArgs(event)

    assert.Equal(t, sensu.CheckStateOK, state)
    assert.NoError(t, err)
    validate.AssertExpectations(t)
}

func TestCheckArgs_EmptyHostname_ReturnsWarningAndError(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = ""
    plugin.Critical = 3
    plugin.Warning = 7

    state, err := checkArgs(event)

    expectedState := sensu.CheckStateWarning
    expectedErr := fmt.Errorf("--hostname is required")

    assert.Equal(t, expectedState, state)
    assert.EqualError(t, err, expectedErr.Error())
}

func TestCheckArgs_InvalidHostname_ReturnsWarningAndError(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = "invalidhostname"
    plugin.Critical = 3
    plugin.Warning = 7

    validate = &mockValidator{}
    validate.On("Var", plugin.Host, "fqdn").Return(fmt.Errorf("hostname is not a valid FQDN"))

    state, err := checkArgs(event)

    expectedState := sensu.CheckStateWarning
    expectedErr := fmt.Errorf("hostname is not a valid FQDN")

    assert.Equal(t, expectedState, state)
    assert.EqualError(t, err, expectedErr.Error())
    validate.AssertExpectations(t)
}

func TestCheckArgs_MissingCritical_ReturnsWarningAndError(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = "example.com"
    plugin.Critical = 0
    plugin.Warning = 7

    state, err := checkArgs(event)

    expectedState := sensu.CheckStateWarning
    expectedErr := fmt.Errorf("--critical is required")

    assert.Equal(t, expectedState, state)
    assert.EqualError(t, err, expectedErr.Error())
}

func TestCheckArgs_MissingWarning_ReturnsWarningAndError(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = "example.com"
    plugin.Critical = 3
    plugin.Warning = 0

    state, err := checkArgs(event)

    expectedState := sensu.CheckStateWarning
    expectedErr := fmt.Errorf("--warning is required")

    assert.Equal(t, expectedState, state)
    assert.EqualError(t, err, expectedErr.Error())
}

func TestCheckArgs_WarningLowerThanCritical_ReturnsWarningAndError(t *testing.T) {
    event := &corev2.Event{}

    plugin.Host = "example.com"
    plugin.Critical = 7
    plugin.Warning = 3

    state, err := checkArgs(event)

    expectedState := sensu.CheckStateWarning
    expectedErr := fmt.Errorf("warning cannot be lower than Critical value")

    assert.Equal(t, expectedState, state)
    assert.EqualError(t, err, expectedErr.Error())
}

func main() {
	
}
