import { useState, type FormEvent } from "react";
import {
  IconAlertTriangle,
  IconArrowDown,
  IconCheck,
  IconFileSearch,
  IconRefresh,
} from "@tabler/icons-react";
import { ApiError } from "@/lib/api";
import { useInspectTransactionMutation } from "@/lib/hooks";
import type {
  TransactionPrevout,
  TransactionReview,
  TransactionReviewRequest,
} from "@/lib/types";

function errorMessage(error: unknown): string {
  return error instanceof ApiError
    ? `${error.code}: ${error.message}`
    : error instanceof Error
      ? error.message
      : "交易检查失败";
}

function ReviewResult({ review }: { review: TransactionReview }) {
  return (
    <div className="inspector-result" aria-live="polite">
      <div className="result-heading">
        <div className="result-icon" data-safe={review.signing_allowed}>
          {review.signing_allowed ? <IconCheck size={15} /> : <IconAlertTriangle size={15} />}
        </div>
        <div>
          <strong>{review.signing_allowed ? "允许进入签名流程" : "交易已被阻止"}</strong>
          <span>{review.network} · SIGHASH_{review.sighash_type.toUpperCase()}</span>
        </div>
      </div>

      <dl className="metric-grid">
        <div><dt>输入 / 输出</dt><dd>{review.input_count} / {review.output_count}</dd></div>
        <div><dt>矿工费</dt><dd>{review.fee_sat.toLocaleString()} sat</dd></div>
        <div><dt>费率</dt><dd>{(review.fee_rate_milli_sat_vb / 1000).toFixed(3)} sat/vB</dd></div>
        <div><dt>RBF</dt><dd>{review.signals_rbf ? "已启用" : "未启用"}</dd></div>
      </dl>

      <div className="hash-block">
        <span>钱包计算的签名摘要</span>
        <code>{review.sighash_hex}</code>
      </div>

      {review.warnings.length > 0 ? (
        <div className="warning-list">
          {review.warnings.map((warning, index) => (
            <div key={`${warning.code}-${index}`}>
              <IconAlertTriangle size={14} />
              <p><strong>{warning.code}</strong>{warning.message}</p>
            </div>
          ))}
        </div>
      ) : (
        <p className="quiet-note"><IconCheck size={14} /> 钱包节点未返回警告</p>
      )}

      <details className="review-details">
        <summary>查看资金流</summary>
        <div className="flow-list">
          {review.inputs.map((input) => (
            <div key={`input-${input.index}`}>
              <IconArrowDown size={14} />
              <span>输入 {input.index}</span>
              <strong>{input.value_sat.toLocaleString()} sat</strong>
            </div>
          ))}
          {review.outputs.map((output) => (
            <div key={`output-${output.index}`}>
              <IconArrowDown className="flow-output" size={14} />
              <span>输出 {output.index}</span>
              <strong>{output.value_sat.toLocaleString()} sat</strong>
            </div>
          ))}
        </div>
      </details>
    </div>
  );
}

export function TransactionInspector() {
  const inspect = useInspectTransactionMutation();
  const [rawTxHex, setRawTxHex] = useState("");
  const [prevoutsJson, setPrevoutsJson] = useState("[]");
  const [inputIndex, setInputIndex] = useState("0");
  const [maxFeeSat, setMaxFeeSat] = useState("10000");
  const [formError, setFormError] = useState<string | null>(null);

  function request(): TransactionReviewRequest | null {
    try {
      const prevouts = JSON.parse(prevoutsJson) as unknown;
      if (!Array.isArray(prevouts)) throw new Error("Prevouts 必须是 JSON 数组");
      const index = Number(inputIndex);
      const feeLimit = Number(maxFeeSat);
      if (!Number.isSafeInteger(index) || index < 0) throw new Error("签名输入序号无效");
      if (!Number.isSafeInteger(feeLimit) || feeLimit < 0) throw new Error("费用上限无效");
      if (!rawTxHex.trim()) throw new Error("请粘贴未签名交易的十六进制数据");
      return {
        raw_tx_hex: rawTxHex.trim().toLowerCase(),
        prevouts: prevouts as TransactionPrevout[],
        input_index: index,
        max_fee_sat: feeLimit,
      };
    } catch (error) {
      setFormError(errorMessage(error));
      return null;
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    setFormError(null);
    const payload = request();
    if (!payload) return;
    inspect.mutate(payload, { onError: (error) => setFormError(errorMessage(error)) });
  }

  return (
    <div className="inspector-scroll">
      <div className="inspector-intro">
        <IconFileSearch size={17} />
        <p>由钱包节点重新解析交易，并自行计算 BIP341 签名摘要。这里不接受手填摘要。</p>
      </div>
      <form className="inspector-form" onSubmit={submit}>
        <label>
          <span>未签名交易</span>
          <textarea
            rows={5}
            value={rawTxHex}
            onChange={(event) => setRawTxHex(event.target.value)}
            placeholder="粘贴 raw transaction hex"
            spellCheck={false}
          />
        </label>
        <label>
          <span>按输入顺序排列的 Prevouts</span>
          <textarea
            rows={5}
            value={prevoutsJson}
            onChange={(event) => setPrevoutsJson(event.target.value)}
            spellCheck={false}
          />
        </label>
        <div className="field-pair">
          <label>
            <span>签名输入</span>
            <input type="number" min={0} value={inputIndex} onChange={(event) => setInputIndex(event.target.value)} />
          </label>
          <label>
            <span>费用上限（sat）</span>
            <input type="number" min={0} value={maxFeeSat} onChange={(event) => setMaxFeeSat(event.target.value)} />
          </label>
        </div>
        {formError ? <p className="form-error"><IconAlertTriangle size={14} />{formError}</p> : null}
        <button className="primary-action" type="submit" disabled={inspect.isPending}>
          {inspect.isPending ? <IconRefresh className="spin" size={15} /> : <IconFileSearch size={15} />}
          {inspect.isPending ? "正在检查" : "检查交易"}
        </button>
      </form>
      {inspect.data ? <ReviewResult review={inspect.data} /> : null}
    </div>
  );
}
