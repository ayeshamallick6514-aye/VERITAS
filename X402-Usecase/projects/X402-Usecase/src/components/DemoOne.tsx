import TextBlockAnimation from "@/components/ui/text-block-animation";
import { ArrowDown } from "lucide-react";

export default function DemoOne() {
  return (
    <div className="min-h-screen w-full bg-white text-zinc-900 flex flex-col font-sans selection:bg-indigo-500 selection:text-white">
      {/* MAIN CONTENT */}
      <div className="flex-1 flex flex-col">
        {/* 1. HERO SECTION: The Hook */}
        <section className="min-h-screen flex flex-col items-center justify-center relative px-6">
          <div className="max-w-4xl w-full">
            <TextBlockAnimation
              blockColor="#000000"
              animateOnScroll={false}
              delay={0.2}
              duration={0.8}
            >
              <h1 className="text-5xl md:text-7xl lg:text-8xl font-black tracking-tighter leading-tight text-black">
                Don&apos;t just inform.
                <br />
                <span className="inline-block bg-black text-white px-4 pb-2 pt-1 rounded-md mt-3 tracking-tight">
                  Captivate.
                </span>
              </h1>
            </TextBlockAnimation>
          </div>

          {/* Scroll Indicator */}
          <div className="absolute bottom-12 flex flex-col items-center gap-2 opacity-60">
            <span className="text-[11px] uppercase tracking-widest text-zinc-500 font-medium">
              Scroll to Reveal
            </span>
            <ArrowDown className="w-5 h-5 text-zinc-500 animate-bounce" />
          </div>
        </section>

        {/* 2. THE PITCH */}
        <section className="min-h-[80vh] flex flex-col justify-center items-center px-6 py-24 bg-white border-t border-zinc-100">
          <div className="max-w-3xl w-full space-y-16">
            <TextBlockAnimation blockColor="#10b981" duration={0.7}>
              <h2 className="text-3xl md:text-4xl lg:text-5xl font-bold text-black">
                This is what I do.
              </h2>
            </TextBlockAnimation>

            <TextBlockAnimation blockColor="#f59e0b" stagger={0.03}>
              <p className="text-lg md:text-2xl leading-relaxed text-zinc-700">
                You stopped scrolling because the motion caught your eye.
                That&apos;s the power of <strong>GSAP</strong> and <strong>React</strong> properly combined.
                I build bespoke animations like this for clients who aren&apos;t satisfied with &quot;standard.&quot;
              </p>
            </TextBlockAnimation>

            <div className="pl-6 border-l-2 border-indigo-500">
              <TextBlockAnimation blockColor="#6366f1" duration={0.6}>
                <p className="text-base md:text-lg italic text-zinc-500">
                  &quot;If you want your website to feel alive, we should talk.&quot;
                </p>
              </TextBlockAnimation>
            </div>
          </div>
        </section>

        {/* 3. FOOTER: Call to Action */}
        <footer className="h-[40vh] md:h-[50vh] flex items-center justify-center border-t border-zinc-200 bg-white">
          <TextBlockAnimation blockColor="#ef4444" duration={0.8}>
            <a
              href="mailto:hello@daiwiik.com"
              className="text-4xl md:text-6xl lg:text-7xl font-black hover:text-indigo-600 transition-colors cursor-pointer text-black"
            >
              Let&apos;s Build It.
            </a>
          </TextBlockAnimation>
        </footer>
      </div>
    </div>
  );
}
