import Foundation
import SwiftParser
import SwiftSyntax

struct SourceInput: Codable { let path: String; let source: String }
struct ReviewInput: Codable { let version: Int; let files: [SourceInput] }
struct Finding: Codable, Equatable {
    let rule: String
    let file: String
    let offset: Int
    let length: Int
    let line: Int
    let column: Int
}
struct FileResult: Codable {
    let path: String
    let parsed: Bool
}
struct ReviewOutput: Codable {
    let version: Int
    let analyzer: String
    let files: [FileResult]
    let findings: [Finding]
    let truncated: Bool
}

/// Syntax-only rules. No macro expansion, type checking, project execution or filesystem access.
/// Locations are UTF-8 byte positions into exactly the source supplied by the daemon.
enum Analyzer {
    static let version = "1.0.0-swiftsyntax603.0.1"
    static func review(_ input: ReviewInput) -> ReviewOutput {
        var results: [FileResult] = []
        var findings: [Finding] = []
        var truncated = false
        for file in input.files {
            let tree = Parser.parse(source: file.source)
            results.append(FileResult(path: file.path, parsed: !tree.hasError))
            guard !tree.hasError else { continue }
            let visitor = RuleVisitor(file: file.path, tree: tree)
            visitor.walk(tree)
            let remaining = max(0, 1000 - findings.count)
            findings.append(contentsOf: visitor.findings.prefix(remaining))
            truncated = truncated || visitor.truncated || visitor.findings.count > remaining
        }
        return ReviewOutput(version: 1, analyzer: version, files: results,
                            findings: findings, truncated: truncated)
    }
}

private final class RuleVisitor: SyntaxVisitor {
    let file: String
    let converter: SourceLocationConverter
    let importsSwiftUI: Bool
    let shadowedNames: Set<String>
    var findings: [Finding] = []
    var truncated = false

    init(file: String, tree: SourceFileSyntax) {
        self.file = file
        converter = SourceLocationConverter(fileName: file, tree: tree)
        importsSwiftUI = tree.statements.contains {
            $0.item.as(ImportDeclSyntax.self)?.path.trimmedDescription == "SwiftUI"
        }
        let declarations = DeclarationNames()
        declarations.walk(tree)
        shadowedNames = declarations.names
        super.init(viewMode: .sourceAccurate)
    }

    func emit(_ rule: String, _ node: some SyntaxProtocol) {
        guard findings.count < 1000 else { truncated = true; return }
        let start = node.positionAfterSkippingLeadingTrivia
        let loc = converter.location(for: start)
        findings.append(Finding(rule: rule, file: file, offset: start.utf8Offset,
                                length: node.endPositionBeforeTrailingTrivia.utf8Offset - start.utf8Offset,
                                line: loc.line, column: loc.column))
    }

    override func visit(_ node: VariableDeclSyntax) -> SyntaxVisitorContinueKind {
        // Stored UUIDs are stable for the instance and are deliberately not flagged.
        guard !shadowedNames.contains("UUID"), !shadowedNames.contains("Identifiable"),
              let member = node.parent?.as(MemberBlockItemSyntax.self),
              let block = member.parent?.parent?.as(MemberBlockSyntax.self) else { return .visitChildren }
        let inheritance: InheritanceClauseSyntax?
        if let declaration = block.parent?.as(StructDeclSyntax.self) { inheritance = declaration.inheritanceClause }
        else if let declaration = block.parent?.as(ClassDeclSyntax.self) { inheritance = declaration.inheritanceClause }
        else { return .visitChildren }
        guard inheritance?.inheritedTypes.contains(where: {
            ["Identifiable", "Swift.Identifiable"].contains($0.type.trimmedDescription)
        }) == true else { return .visitChildren }
        for binding in node.bindings where binding.pattern.trimmedDescription == "id" {
            guard let accessors = binding.accessorBlock else { continue }
            let statements: CodeBlockItemListSyntax?
            switch accessors.accessors {
            case .getter(let body): statements = body
            case .accessors(let list): statements = list.first(where: { $0.accessorSpecifier.text == "get" })?.body?.statements
            }
            guard let statements, statements.count == 1, let item = statements.first else { continue }
            let expression = item.item.as(ExprSyntax.self) ?? item.item.as(ReturnStmtSyntax.self)?.expression
            if isUUID(expression) { emit("swift.identity.computed-uuid", binding) }
        }
        return .visitChildren
    }

    override func visit(_ node: FunctionCallExprSyntax) -> SyntaxVisitorContinueKind {
        guard importsSwiftUI, insideViewBody(node) else { return .visitChildren }
        if let member = node.calledExpression.as(MemberAccessExprSyntax.self), member.declName.baseName.text == "id",
           node.arguments.count == 1, isUUID(node.arguments.first?.expression), !shadowedNames.contains("UUID") {
            emit("swiftui.identity.fresh-id", node)
        }
        // Limit performance advice to the ForEach input/row. Generic filtering elsewhere is not a defect.
        if named(node, "ForEach"), !shadowedNames.contains("ForEach") {
            if let collection = node.arguments.first?.expression.as(FunctionCallExprSyntax.self),
               let member = collection.calledExpression.as(MemberAccessExprSyntax.self),
               ["filter", "sorted"].contains(member.declName.baseName.text) {
                emit("swiftui.performance.inline-collection", collection)
            }
            if isListRow(node), let body = node.trailingClosure?.statements {
                for item in body {
                    if item.item.as(ExpressionStmtSyntax.self)?.expression.is(IfExprSyntax.self) == true
                        || item.item.is(IfExprSyntax.self) {
                        emit("swiftui.performance.variable-rows", item)
                    }
                    if let call = item.item.as(FunctionCallExprSyntax.self), named(call, "AnyView"),
                       !shadowedNames.contains("AnyView") {
                        emit("swiftui.performance.erased-row", call)
                    }
                }
            }
        }
        return .visitChildren
    }

    private func named(_ call: FunctionCallExprSyntax, _ name: String) -> Bool {
        [name, "SwiftUI." + name].contains(call.calledExpression.trimmedDescription)
    }
    private func isUUID(_ expression: ExprSyntax?) -> Bool {
        guard let call = expression?.as(FunctionCallExprSyntax.self), call.arguments.isEmpty,
              call.trailingClosure == nil else { return false }
        return ["UUID", "Foundation.UUID"].contains(call.calledExpression.trimmedDescription)
    }
    private func insideViewBody(_ node: some SyntaxProtocol) -> Bool {
        var parent = node.parent
        while let current = parent {
            // Action callbacks and helpers do not execute as part of the immediate body expression.
            if let closure = current.as(ClosureExprSyntax.self),
               let call = closure.parent?.as(FunctionCallExprSyntax.self),
               let member = call.calledExpression.as(MemberAccessExprSyntax.self),
               ["onAppear", "onDisappear", "onChange", "task", "onTapGesture"].contains(member.declName.baseName.text) {
                return false
            }
            if current.is(FunctionDeclSyntax.self) { return false }
            if let binding = current.as(PatternBindingSyntax.self) {
                guard binding.pattern.trimmedDescription == "body",
                      binding.typeAnnotation?.type.trimmedDescription == "some View"
                        || binding.typeAnnotation?.type.trimmedDescription == "some SwiftUI.View" else { return false }
                var ancestor = current.parent
                while let value = ancestor {
                    if let declaration = value.as(StructDeclSyntax.self) {
                        return !shadowedNames.contains("View") && declaration.inheritanceClause?.inheritedTypes.contains {
                            ["View", "SwiftUI.View"].contains($0.type.trimmedDescription)
                        } == true
                    }
                    ancestor = value.parent
                }
                return false
            }
            parent = current.parent
        }
        return false
    }
    private func isListRow(_ node: FunctionCallExprSyntax) -> Bool {
        // Only direct List content: a stack or custom container changes the child-count semantics.
        guard !shadowedNames.contains("List"),
              let item = node.parent?.as(CodeBlockItemSyntax.self),
              let closure = item.parent?.parent?.as(ClosureExprSyntax.self),
              let call = closure.parent?.as(FunctionCallExprSyntax.self) else { return false }
        return named(call, "List")
    }
}

private final class DeclarationNames: SyntaxVisitor {
    var names: Set<String> = []
    init() { super.init(viewMode: .sourceAccurate) }
    override func visit(_ node: StructDeclSyntax) -> SyntaxVisitorContinueKind { names.insert(node.name.text); return .visitChildren }
    override func visit(_ node: ClassDeclSyntax) -> SyntaxVisitorContinueKind { names.insert(node.name.text); return .visitChildren }
    override func visit(_ node: EnumDeclSyntax) -> SyntaxVisitorContinueKind { names.insert(node.name.text); return .visitChildren }
    override func visit(_ node: TypeAliasDeclSyntax) -> SyntaxVisitorContinueKind { names.insert(node.name.text); return .visitChildren }
    override func visit(_ node: FunctionDeclSyntax) -> SyntaxVisitorContinueKind { names.insert(node.name.text); return .visitChildren }
}
