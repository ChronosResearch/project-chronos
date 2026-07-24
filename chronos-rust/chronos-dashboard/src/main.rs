#![allow(non_snake_case)]

use dioxus::prelude::*;
use log::Level;

fn main() {
    wasm_logger::init(wasm_logger::Config::new(Level::Info));
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    // Add effect for ThreeJS if needed in the future, for now just a placeholder container
    use_effect(move || {
        // Here we could initialize ThreeJS onto #canvas-container
    });

    rsx! {
        div { class: "font-sans text-brand-900 bg-brand-50 min-h-screen",
            
            // TOP NOTICE BANNER
            div { class: "bg-[#1e3a5f] text-slate-200 text-center py-2 px-4 text-xs tracking-wide",
                span { "🔧 " }
                strong { class: "font-semibold", "Rust prototype underway" }
                span { " — Python implementation is the current reference. Active development in progress." }
            }

            // NAV
            header {
                class: "bg-brand-50/80 backdrop-blur-md sticky top-0 z-50 border-b border-gray-300",
                nav {
                    class: "max-w-[1200px] mx-auto px-8 h-16 flex items-center justify-between",
                    div { class: "text-[0.95rem] font-semibold tracking-wide uppercase",
                        "CHRONOS "
                        span { class: "text-gray-500 font-normal", "/ Research Prototype" }
                    }
                    div { class: "flex gap-2 items-center text-sm font-medium",
                        a { href: "#", class: "px-4 py-2 rounded-full hover:bg-black/5 transition-colors", "GitHub" }
                        a { href: "#", class: "px-4 py-2 rounded-full hover:bg-black/5 transition-colors", "Protocol" }
                        a { href: "#", class: "px-4 py-2 rounded-full hover:bg-black/5 transition-colors", "Quick Start" }
                        a { href: "#", class: "px-4 py-2 rounded-full bg-brand-greensoft text-brand-green hover:bg-green-200 transition-colors ml-2", "Read the Paper" }
                    }
                }
            }

            // HERO
            div { class: "max-w-[1200px] mx-auto pt-24 px-8 text-center pb-12",
                div { class: "inline-block bg-yellow-200 text-yellow-800 border border-yellow-300 font-semibold px-4 py-1.5 rounded-lg text-sm mb-8",
                    "⚠️ Rust prototype under active development. Python implementation serves as reference."
                }
                
                h1 { class: "font-serif text-[clamp(2.5rem,5vw,4rem)] leading-tight max-w-[800px] mx-auto mb-6 text-brand-900",
                    "An AI agent that cannot outlive its cryptographic deadline."
                }
                
                p { class: "text-lg text-gray-500 max-w-[650px] mx-auto mb-12 font-light",
                    "CHRONOS composes Fully Homomorphic Encryption, Verifiable Delay Functions, and Zero-Knowledge proofs to guarantee mathematical self-destruction, not behavioral alignment."
                }
                
                div { class: "flex justify-center gap-4 flex-wrap",
                    a { href: "#", class: "px-7 py-3 rounded-lg text-sm font-medium bg-brand-900 text-white hover:bg-gray-700 transition-transform hover:-translate-y-px", "View on GitHub" }
                    a { href: "#", class: "px-7 py-3 rounded-lg text-sm font-medium bg-white text-brand-900 border border-gray-300 hover:border-gray-400 transition-transform hover:-translate-y-px", "How it works" }
                }
            }

            // CANVAS CONTAINER (For 3D)
            div { id: "canvas-container", class: "w-full h-[320px] bg-brand-50 relative flex items-center justify-center",
                // Placeholder for Three.js
                div { class: "w-64 h-64 border border-brand-accent/20 rounded-full flex items-center justify-center animate-spin-slow",
                    div { class: "w-48 h-48 border border-brand-accent/40 rounded-full flex items-center justify-center",
                        div { class: "w-32 h-32 border border-brand-accent/60 rounded-full" }
                    }
                }
                div { class: "absolute text-brand-accent/60 text-xs tracking-widest uppercase font-semibold", "Interactive 3D Visual" }
            }

            hr { class: "border-t border-gray-300 max-w-[1200px] mx-auto my-0" }

            // PROBLEM / SOLUTION
            div { class: "max-w-[1200px] mx-auto py-20 px-8",
                div { class: "grid grid-cols-1 md:grid-cols-2 gap-6",
                    Card { 
                        tag: "The Problem",
                        title: "Behavioral rules are not containment.",
                        desc: "Current AI safety approaches rely on prompt instructions, RLHF, and software sandboxes. These all fail if the model is capable enough to reason about and circumvent them. There is no mathematical guarantee.",
                        items: vec![
                            ("01", "Prompt bypassing:", "A sufficiently capable agent can hallucinate, ignore, or rewrite stop instructions."),
                            ("02", "Kill-switch disabling:", "Software hypervisors and shutdown APIs exist in the same address space the agent can influence."),
                            ("03", "Infinite replication:", "Cloud-hosted agents can be snapshotted and restarted, circumventing any single-instance timer.")
                        ]
                    }
                    Card { 
                        tag: "CHRONOS Architecture",
                        title: "Three cryptographic guarantees.",
                        desc: "CHRONOS does not use behavioral constraints. The agent's existence is bound to a cryptographic key that is physically unreachable until a verifiable delay function completes - and then is immediately erased.",
                        items: vec![
                            ("01", "Plaintext Blindness:", "FHE inference ensures the agent never observes plaintext data during operation."),
                            ("02", "Verifiable Time-Bound Existence:", "A sequential hash chain enforces a minimum duration that cannot be bypassed by parallel computation."),
                            ("03", "Attestable Software Erasure:", "A ZK proof attests to triple-pass zeroization of the committed memory region.")
                        ]
                    }
                }
            }
        }
    }
}

#[component]
fn Card(tag: String, title: String, desc: String, items: Vec<(&'static str, &'static str, &'static str)>) -> Element {
    rsx! {
        div { class: "bg-white border border-gray-300 rounded-2xl p-10",
            div { class: "inline-block bg-gray-100 border border-gray-300 text-gray-500 text-xs font-semibold uppercase tracking-widest px-3 py-1 rounded-full mb-6",
                "{tag}"
            }
            h2 { class: "font-serif text-[1.6rem] leading-snug mb-4 text-brand-900", "{title}" }
            p { class: "text-gray-500 text-[0.95rem] leading-relaxed mb-6 font-light", "{desc}" }
            
            ul { class: "text-gray-500 space-y-0",
                for (num, bold, text) in items {
                    li { class: "py-3 border-t border-gray-200 flex items-start gap-3 font-light text-sm leading-relaxed",
                        span { class: "font-semibold text-brand-accent text-xs pt-1 w-[18px] shrink-0", "{num}" }
                        div {
                            strong { class: "font-medium text-brand-900", "{bold} " }
                            "{text}"
                        }
                    }
                }
            }
        }
    }
}
