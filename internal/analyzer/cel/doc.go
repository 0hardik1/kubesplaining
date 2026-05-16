// Package cel wires the user-supplied CEL rules loader/evaluator (in
// internal/rules/cel) into the analyzer engine's module set. It implements the
// Module interface (Name + Analyze) so the engine can fan it out alongside the
// built-in analyzers.
//
// The module's Name is "custom-rules" (operator-facing, used by
// --only-modules / --skip-modules); the package name is "cel" (developer-facing,
// reflects the underlying expression language).
//
// When the operator does not pass --custom-rules, the module is registered
// with an empty rules directory and Analyze returns (nil, nil), keeping the
// scan output byte-identical to a build without the module.
package cel
