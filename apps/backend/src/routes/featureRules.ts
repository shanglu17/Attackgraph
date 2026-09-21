import { Router } from "express";
import { ZodError } from "zod";
import { PreviewReferenceError } from "../services/featureRules/contract.js";
import { evaluateFeatureRules } from "../services/featureRules/evaluate.js";

const router = Router();
router.post("/analysis/feature-rules/preview", (req, res, next) => {
  try {
    return res.json(evaluateFeatureRules(req.body));
  } catch (error) {
    if (error instanceof ZodError) return res.status(400).json({
      message: "特征规则预览输入不符合契约", issues: error.issues
    });
    if (error instanceof PreviewReferenceError) return res.status(400).json({
      message: error.message, issues: [{ path: [], message: error.message }]
    });
    return next(error);
  }
});
export default router;
