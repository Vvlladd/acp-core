import Testing
@testable import ACPSwiftChecks

private func review(_ source: String) -> ReviewOutput {
    Analyzer.review(ReviewInput(version: 1, files: [.init(path: "Customer/App.swift", source: source)]))
}

@Test func stableAndComputedIdentity() {
    #expect(review("import Foundation\nstruct Item: Identifiable { var id: UUID { UUID() } }").findings.map(\.rule) == ["swift.identity.computed-uuid"])
    #expect(review("struct Item: Identifiable { let id = UUID() }").findings.isEmpty)
    #expect(review("struct Item { var id: UUID { UUID() } }").findings.isEmpty)
    #expect(review("struct UUID {}\nstruct Item: Identifiable { var id: UUID { UUID() } }").findings.isEmpty)
}

@Test func swiftUIRulesAndLocations() {
    let source = """
    import SwiftUI
    struct CustomerView: View {
        var body: some View {
            List {
                ForEach(items.filter { $0.visible }) { item in
                    if item.visible { Text("🐈") }
                    AnyView(Text(item.name))
                }
            }.id(UUID())
        }
    }
    """
    let output = review(source)
    #expect(Set(output.findings.map(\.rule)) == ["swiftui.identity.fresh-id", "swiftui.performance.inline-collection", "swiftui.performance.variable-rows", "swiftui.performance.erased-row"])
    #expect(output.findings.allSatisfy { $0.line > 0 && $0.column > 0 && $0.length > 0 })
    #expect(output.findings == review(source).findings)
    for finding in output.findings {
        let bytes = Array(source.utf8)
        #expect(String(bytes: bytes[finding.offset..<(finding.offset + finding.length)], encoding: .utf8) != nil)
    }
}

@Test func exceptionsAndComments() {
    let source = """
    import SwiftUI
    struct CustomerView: View {
        var body: some View {
            List {
                ForEach(items) { item in
                    VStack { if item.visible { Text(item.name) } }
                }
            }.onAppear { _ = Text("hi").id(UUID()) }
        }
        func later() { _ = AnyView(Text("hi")) }
    }
    // var id: UUID { UUID() }
    """
    #expect(review(source).findings.isEmpty)
    #expect(review(source.replacingOccurrences(of: "List {", with: "VStack {")).findings.isEmpty)
}

@Test func malformedInputDoesNotPass() {
    let result = review("struct Broken {")
    #expect(result.files.first?.parsed == false)
    #expect(result.findings.isEmpty)
}

@Test func lifecycleModifierOnlyExcludesItsCallback() {
    let source = """
    import SwiftUI
    struct CustomerView: View {
        var body: some View {
            Text("Hello").id(UUID()).onAppear { _ = Text("Callback").id(UUID()) }
        }
    }
    """
    let findings = review(source).findings
    #expect(findings.count == 1)
    #expect(findings.first?.rule == "swiftui.identity.fresh-id")
}
