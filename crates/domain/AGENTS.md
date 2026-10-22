# Domain crate working contract

Keep this crate free of I/O, OS APIs, process control, credentials and UI
concerns. New domain rules land as pure functions with focused unit tests;
errors stay typed via thiserror. Application orchestration belongs to
`crates/application`, never here. Run the workspace `just check` before review.
