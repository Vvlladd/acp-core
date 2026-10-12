use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule<T = String> {
    pub id: T,
    pub title: T,
    pub category: T,
    pub severity: T,
    pub explanation: T,
    pub guidance: T,
    pub before: T,
    pub after: T,
    pub reference: T,
}

pub const RULES: &[Rule<&str>] = &[
    Rule { id: "swift.identity.computed-uuid", title: "Identity changes on every read", category: "Identity", severity: "warning",
        explanation: "This Identifiable getter directly creates a new UUID. Consumers can observe a different identity each time they read it.",
        guidance: "Store an identifier for the lifetime of the model, or return a stable identifier from your data. This syntax check does not resolve types outside this file.",
        before: "var id: UUID { UUID() }", after: "let id = UUID()",
        reference: "https://developer.apple.com/videos/play/wwdc2021/10022/" },
    Rule { id: "swiftui.identity.fresh-id", title: "Fresh identity during view construction", category: "Identity", severity: "warning",
        explanation: "The view's id modifier directly receives a new UUID when this expression is evaluated. Changing identity can recreate view state.",
        guidance: "Use a stable model identifier. If resetting state is intentional, tie the reset identifier to that action rather than every body evaluation.",
        before: "DetailView().id(UUID())", after: "DetailView().id(item.id)",
        reference: "https://developer.apple.com/videos/play/wwdc2021/10022/" },
    Rule { id: "swiftui.performance.variable-rows", title: "Conditional rows inside a List iteration", category: "Rendering", severity: "consideration",
        explanation: "A direct conditional in this ForEach can produce a variable number of List rows. SwiftUI may need to evaluate more elements to determine the row count.",
        guidance: "Consider preparing the displayed collection before building rows, or use a single row container when that matches the intended layout. Measure before changing behavior.",
        before: "ForEach(items) { item in\n    if item.visible { Row(item: item) }\n}",
        after: "ForEach(visibleItems) { item in\n    Row(item: item)\n}",
        reference: "https://developer.apple.com/videos/play/wwdc2023/10160/" },
    Rule { id: "swiftui.performance.inline-collection", title: "Collection work in view construction", category: "Rendering", severity: "consideration",
        explanation: "This ForEach input directly sorts or filters its collection during body evaluation. For large collections or frequent updates this can add repeated work.",
        guidance: "Measure the cost. If significant, prepare derived data when its inputs change. Small collections and inexpensive transformations can be appropriate inline.",
        before: "ForEach(items.filter { $0.visible }) { Row(item: $0) }",
        after: "ForEach(visibleItems) { Row(item: $0) }",
        reference: "https://developer.apple.com/videos/play/wwdc2023/10160/" },
    Rule { id: "swiftui.performance.erased-row", title: "Type-erased List row", category: "Rendering", severity: "consideration",
        explanation: "This direct List row is wrapped in AnyView. Type erasure can hide structural information used by SwiftUI's list optimizations.",
        guidance: "Prefer a concrete row View or a ViewBuilder when possible. Type erasure may be intentional; assess the API boundary and measure performance.",
        before: "ForEach(items) { AnyView(Row(item: $0)) }",
        after: "ForEach(items) { Row(item: $0) }",
        reference: "https://developer.apple.com/videos/play/wwdc2023/10160/" },
];

pub fn find(id: &str) -> Option<&'static Rule<&'static str>> {
    RULES.iter().find(|r| r.id == id)
}
