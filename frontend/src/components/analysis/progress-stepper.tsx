"use client";

import { cn } from "@/lib/utils";
import { Check, Loader2, Circle } from "lucide-react";
import { motion } from "framer-motion";

export type StepStatus = "pending" | "running" | "completed" | "error";

export interface AnalysisStep {
  id: string;
  label: string;
  status: StepStatus;
  description?: string;
}

interface ProgressStepperProps {
  steps: AnalysisStep[];
}

export function ProgressStepper({ steps }: ProgressStepperProps) {
  return (
    <div className="w-full max-w-3xl mx-auto py-8">
      <div className="relative">
        {/* Connecting Line */}
        <div className="absolute top-5 left-6 bottom-5 w-0.5 bg-border -z-10" />
        
        <div className="space-y-6">
          {steps.map((step, index) => {
            const isCompleted = step.status === "completed";
            const isRunning = step.status === "running";
            const isError = step.status === "error";
            const isPending = step.status === "pending";

            return (
              <motion.div
                key={step.id}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className="flex items-start"
              >
                <div className="flex-shrink-0 w-12 h-12 flex items-center justify-center bg-background">
                  <div
                    className={cn(
                      "w-10 h-10 rounded-full flex items-center justify-center border-2 transition-colors duration-300",
                      isCompleted && "bg-primary border-primary text-primary-foreground",
                      isRunning && "border-primary text-primary",
                      isError && "border-destructive text-destructive",
                      isPending && "border-muted-foreground/30 text-muted-foreground"
                    )}
                  >
                    {isCompleted ? (
                      <Check className="w-5 h-5" />
                    ) : isRunning ? (
                      <Loader2 className="w-5 h-5 animate-spin" />
                    ) : (
                      <Circle className="w-3 h-3 fill-current" />
                    )}
                  </div>
                </div>
                <div className="ml-4 mt-2">
                  <h4
                    className={cn(
                      "text-base font-semibold",
                      (isCompleted || isRunning) ? "text-foreground" : "text-muted-foreground",
                      isError && "text-destructive"
                    )}
                  >
                    {step.label}
                  </h4>
                  {step.description && (
                    <p className="text-sm text-muted-foreground mt-1">
                      {step.description}
                    </p>
                  )}
                </div>
              </motion.div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
