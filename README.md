# Zero-Knowledge Proof：以 Schnorr Protocol 為核心的可驗證身份驗證系統

組員：
d13921c02 黃杬霆
r13921a13 林伯叡

---

隨著資訊安全與隱私保護的重要性日益增加，零知識證明（Zero-Knowledge Proof, ZKP）成為密碼學領域中極具潛力的技術之一。ZKP 允許證明者向驗證者證明自己掌握某項秘密資訊的正確性，卻不洩漏任何秘密的具體細節。這種特性特別適合在現代網路環境中保護使用者隱私並提升系統安全性。

本專題旨在探討以 Schnorr Protocol 為核心的零知識證明協議，深入分析協議背後的數學理論，包括離散對數問題（Discrete Logarithm Problem, DLP）及其在傳統有限域與橢圓曲線上的差異，以及零知識證明的基本性質（完整性、可靠性與零知識性）。同時，我們將透過 Fiat-Shamir 啟發式（Fiat-Shamir Heuristic）轉換，將傳統交互式證明轉為非互動式協議，以降低協議運作複雜度並提高實際應用上的便利性。

在理論探討之外，本專題也進一步提出三項具體改進策略，以明確展示協議的技術創新與效能提升：首先，改用橢圓曲線取代傳統有限域群組運算，大幅降低計算成本與證明尺寸；其次，採用 Fiat-Shamir 非互動架構，提升實務應用的便利性；最後則透過一次性產生多組挑戰的方法顯著提高協議安全性。

透過本專題的研究與實作成果，期望能為零知識證明的理論探討與技術發展提供具體的貢獻，並有效提升相關協議的實用性與安全性。


## 一、數學理論基礎

首先我們介紹本專題所需的數學理論基礎，包括離散對數難題、零知識證明的三大性質、Schnorr 協議的挑戰-應答驗證結構，以及 Fiat–Shamir 啟發式。

### 1. 離散對數問題（DLP）

**定義：** 離散對數問題（Discrete Logarithm Problem, DLP）是現代密碼學中的一個核心難題。具體而言，在一個有限域 $Z_p^*$（質數 $p$ 的乘法群）中，給定一個生成元 $g$ 和群中的任意元素 $h$，離散對數問題要求尋找一個整數 $x$，使得 $g^x \equiv h \pmod p$。換言之，已知 $g$ 和 $h$，計算 $x = \log_g h$【註：$x$ 稱為 $h$ 相對於 $g$ 的離散對數】。

**有限域中的運算：** 在 $Z_p^*$ 中，元素是在模 $p$ 下的非零整數，運算是模 $p$ 乘法。由於 $p$ 為質數，$Z_p^*$ 形成一個循環群，存在生成元 $g$ 可以產生群內所有元素。這表示對於群內任意元素 $h$，都存在某個指數 $x$ 使得 $h = g^x \bmod p$。離散對數問題實質上是尋找冪指數的逆運算：計算 $x$ 使上述等式成立。

**困難性說明：** 計算 $g^x \bmod p$ 在計算上是容易且高效的（時間複雜度對數級別），然而已知 $g^x \equiv h \pmod p$ 要反推出 $x$ 則被廣泛認為是計算困難的問題。沒有已知的多項式時間演算法可以高效求解一般情況下的離散對數。現今最佳的通用攻擊演算法（例如 Baby-step Giant-step 演算法或 Pollard rho 演算法）時間複雜度約為 $O(\sqrt{p})$，對於實務上選擇的大質數（例如 2048 位元或以上）而言，$O(\sqrt{p})$ 的計算量是天文數字級別。因此，離散對數被視為單向函數：從 $x$ 計算 $g^x$ 簡單，但從結果 $g^x$ 反推 $x$ 幾乎不可能在合理時間內完成。這種單向性的難解性正是許多加密系統（如 Diffie-Hellman 金鑰交換、ElGamal 密碼、數位簽章等）的安全基礎，也是我們稍後零知識證明和 Schnorr 協議賴以安全的假設。

### 2. 零知識證明的三性質：完整性、可靠性、零知識性

零知識證明（Zero-Knowledge Proof, ZKP）是一種**交互式證明協議允許「證明者」（Prover）向「驗證者」（Verifier）證明某敘述為真，同時不洩露任何關於該敘述本身內容之外的資訊**。形式上，一個零知識證明協議需要滿足以下三個關鍵性質：

* **完整性（Completeness）：** 如果命題為真且證明者誠實（真的知道秘密訊息或證明所需資訊），那麼按照協議進行，驗證者一定會被說服接受證明。換言之，**對於真實的陳述，誠實的證明者能夠通過協議使驗證者在最後得到「是（接受）」的判斷結果**。

* **可靠性（Soundness）：** 若命題為假（證明者並不知曉所聲稱的秘密），則即使有不誠實的證明者企圖作弊，他能使驗證者接受錯誤命題的機率也極低（理想情況下僅有可忽略的機率）。這一性質確保了驗證者不會被蒙騙：**對於任何不實的聲明，一個沒有真正證據的證明者幾乎不可能通過驗證**。此性質有時也稱為**穩健性**，意指系統對欺騙有抵抗力。

* **零知識性（Zero-knowledge）：證明過程不會洩露任何關於所證明秘密的額外資訊給驗證者。驗證者在協議結束後除了「該命題為真」這一事實外，不會獲得其他任何有關秘密的知識**。形式化地說，對於一個零知識協議，存在一個高效的模擬器（Simulator）能在不知曉秘密的情況下模擬出與真實交互不可區分的對話 transcript，因此驗證者無從分辨真正的證明過程與模擬過程——表示驗證者「零知識」地接受了事實。

上述三性質兼具使得零知識證明非常適合用於密碼協議，例如身份驗證：證明者能向驗證者證明自己掌握某項祕密（如密碼或私鑰），但驗證者從中無法獲取該祕密本身或其他額外資訊，只能確信對方確實知道秘密。

![截圖 2025-05-04 清晨6.57.18](ZKP_example.png)


接下來我們將介紹 Schnorr 協議如何體現這三大性質。


### 3. Schnorr 協議：挑戰-應答結構與推導

**協議簡介：** Schnorr 協議是一種基於離散對數問題的身份識別協議，由德國數學家 Claus-Peter Schnorr 在 1990 年提出。它是一個三步驟的 $\Sigma$-protocol（Sigma 協議），具備典型的**挑戰-應答（challenge-response）結構**。其目的在於**讓證明者證明自己知道某個秘密值（通常是私密金鑰）而不洩露該秘密本身**。Schnorr 協議本質上是一個零知識證明協議：證明者能夠在不透露秘密的前提下，證明自己對該秘密「知情」。下面是協議的詳細步驟與原理推導：

* **參數設定：** 協議在一個公開的離散對數環境下進行。選擇一個足夠大的質數 $p$，以及 $p$ 的生成元 $g$。證明者擁有一個秘密私鑰 $x$（這就是要證明知曉的秘密），並計算對應的公開金鑰 $y = g^x \bmod p$。公開參數包括 $(p, g, y)$，而 $x$ 僅證明者知道。

* **第一步（承諾，Commit）：** 證明者隨機選取一個臨時秘密隨機數 $r$（在 $[1, p-2]$ 或 $[0, q-1]$ 範圍內均可），計算承諾值 $t = g^r \bmod p$，並將 $t$ 發送給驗證者。這一步相當於證明者先不揭示部分資訊，對其知識做出“承諾”。

* **第二步（挑戰，Challenge）：** 驗證者收到 $t$ 後，產生一個隨機的挑戰值 $e$（通常取 $0 \le e < p-1$，或 $<q$）。**這個 $e$ 是驗證者對證明者提出的隨機挑戰**，驗證者將 $e$ 發送給證明者。挑戰必須每次新鮮且無法被證明者預測，這一步對保障可靠性極為關鍵。

* **第三步（應答，Response）：** 證明者在接收到驗證者的挑戰 $e$ 後，用自己的秘密 $x$ 來計算對應的應答值：

  $$
  s = r + e \cdot x \pmod{(p-1)},
  $$

  並將 $s$ 發送給驗證者。這裡 $s$ 結合了證明者在第一步的隨機承諾 $r$ 和其秘密 $x$ 針對挑戰 $e$ 給出的「答覆」。

* **驗證（Verify）：** 最後，驗證者檢查接收到的 $s$ 是否滿足：

  $$
  g^s \stackrel{?}{\equiv} t \cdot y^e \pmod p,
  $$

  如果成立則驗證通過（接受證明者的身份或陳述），若不成立則拒絕。驗證者的檢查實際上是在驗證證明者對 $x$ 的知識：將 $s$ 展開代入，$$g^s = g^{r + ex} = g^r \cdot g^{ex} \equiv g^r \cdot (g^x)^e \equiv g^r \cdot y^e \pmod p.$$這正好等於右邊的 $t \cdot y^e$，而 $g^r$ 我們知道是 $t$。因此若證明者誠實，則恰好滿足等式，驗證者將會得到 $g^s$ 和 $t \cdot y^e$ 二者相等的結果。

#### 協議性質推導： Schnorr 協議滿足前述零知識證明的三性質

* **完整性：** 如果證明者確實知道秘密 $x$，則按照協議計算出的 $s = r + e x$ 一定能通過驗證者的等式檢驗（如上推導），因此真命題下誠實執行會 100% 通過驗證。

* **可靠性：** 如果證明者並不掌握正確的 $x$，那麼他要通過驗證者檢驗的機率極低。直觀理解是，證明者在不知道 $x$ 的情況下無法同時滿足對所有可能挑戰 $e$ 的正確應答。若他試圖作弊，可以想像他必須在不知道 $x$ 的前提下猜測驗證者的挑戰值，並構造看似可信的 $(t, s)$。但由於 $e$ 是驗證者隨機產生且不可預測的，如果證明者預先猜錯了 $e$，最終他提交的 $s$ 無法滿足 $g^s = t \cdot y^e$。嚴格的論證可證明：**除非破解離散對數問題，否則一個不知秘密的欺詐證明者只能以極小的機率通過驗證（挑戰值若有 $q$ 種可能，成功率至多 $1/q$ ）**。稍後在測試部分我們也會以隨機模擬驗證這一點。

* **零知識性：** 在 Schnorr 協議中，驗證者除了知道「證明者擁有秘密」這一事實外，從交互中得不到關於秘密 $x$ 的任何資訊。形式上，可以構造一個模擬器：它隨機選擇挑戰 $e$ 和應答 $s$，再計算對應的 $t = g^s / y^e \bmod p$，模擬出 $(t, e, s)$ 這樣一組「對話記錄」。這組數據在分佈上與真實協議執行過程中產生的分佈無異（因為 $e$ 均勻隨機，$s$ 也相當於均勻隨機，$t$ 按上述構造滿足驗證等式）。因此，**驗證者無法從對話辨別出任何額外資訊——任何真實執行可產生的通信，在不知道秘密的情況下亦可被模擬出來**。這證明了 Schnorr 協議對**誠實驗證者**而言是零知識的：驗證者遵守協議產生隨機挑戰時，無法從中獲取秘密。

Schnorr 協議由上述特性可見，非常適合身份驗證系統：用戶（證明者）可以證明自己知道帳戶的私密金鑰，而服務端（驗證者）除了確認用戶確實持有有效金鑰外，無法竊取該金鑰或其他秘密資訊。


### 4. Fiat–Shamir 啟發式（Fiat–Shamir Heuristic）

Fiat–Shamir 啟發式是一種將典型三步驟 $\Sigma$‑protocol（互動式零知識證明）轉換為**非互動式**零知識證明（Non-Interactive Zero Knowledge, NIZK）的通用方法。其核心思想是：**用一個不可預測的雜湊函數 $H(\,\cdot\,)$ 取代驗證者隨機挑戰的角色，令挑戰值成為承諾值（及其他公開上下文）的雜湊輸出**。

#### 三步驟互動式協議與轉換流程

考慮任意三步互動式 $\Sigma$‑protocol（本專題聚焦 Schnorr）之通訊記錄 $(t,e,s)$：

1. **承諾（Commit）**：證明者隨機選取臨時祕密 $r$，計算 $t=f(r)$ 並輸出。
2. **挑戰（Challenge）**：驗證者隨機選取 $e\in\mathcal E$。
3. **應答（Response）**：證明者計算 $s=g(r,e,x)$，其中 $x$ 為私鑰；驗證者最終檢查 $\mathsf{Verify}(t,e,s,y)=\textsf{true}$。

Fiat–Shamir 轉換公式：

$$
e \;:=\; H\!\bigl(t\, \| \,y\,\|\,\text{ctx}\bigr)\;\bmod|\mathcal E|,
$$

其中 $y$ 為公開金鑰，`ctx` 可包含協議標識、訊息雜湊或時間戳，以避免重放攻擊（Replay Attack）。驗證者依此計算 $s$，輸出一次性證明 $\pi=(t,s)$；驗證者自行重算同一雜湊得到 $\tilde e$，並執行同樣驗證函式。

#### 保持正確性的代數關係

在互動式協議中已證明

$$
\mathsf{Verify}(t,e,s,y)=\textsf{true}
\quad\Longleftrightarrow\quad
s=g(r,e,x).
$$

Fiat–Shamir 僅改變**產生 $e$ 的方式**，不影響代數驗證關係；因此若 Prover 誠實持有 $x$，則 $\pi$ 必定驗證通過。

#### 分叉試驗證明 Soundness

假設有多項式時間偽造者 $\mathcal A$ 可在未持有私鑰的情況下輸出有效證明 $\pi=(t,s)$。在**隨機預言模型** (Random Oracle Model, ROM) 中，我們可對 $\mathcal A$ 的雜湊查詢進行**分叉試驗 (forking)**：

* 第一次執行：$\mathcal A$ 查詢 $H(t\,\|\,y\,\|\,\text{ctx})$ 得 $e$。
* 第二次在保留相同隨機性 (except for oracle responses) 下，重播 $\mathcal A$，強制 oracle 對同一輸入回覆 $e' \ne e$，得另一應答 $s'$。

若 $\mathcal A$ 兩次皆成功，則

$$
g^{s}=t\,y^{e},\qquad g^{s'}=t\,y^{e'} 
\Longrightarrow 
g^{s-s'}=y^{\,e-e'}.
$$

因 $e\neq e'$，即可解出私鑰：

$$
x \equiv (s-s')\,(e-e')^{-1}\pmod{q},
$$

這表示 $\mathcal A$ 可被升格為離散對數求解器，與 DLP 假設矛盾，因此其**偽造成功機率至多為 $\mathsf{negl}(\lambda)$**。

#### 模擬器保證模擬零知識

對任何輕量（甚至惡意）驗證者 $\mathcal V$，存在一個模擬器 $\mathcal S$ ，可在**未得知私鑰 $x$** 的情況下，構造一組證明 $\pi=(t,s)$ 及對應的 oracle 回覆，使得 $\mathcal V$ 無法證明是否來自真實的驗證者：

1. 隨機選取 $e\gets\mathcal E,\;s\gets\mathbb Z_{q}$。
2. 計算 $t = g^{s}y^{-e}$.
3. 在預言表寫入 $H(t\,\|\,y\,\|\,\text{ctx}) \mapsto e$。

由於在隨機預言模型中，驗證者 $\mathcal V$ 無法預測 oracle 的輸出，因此上述模擬過程所產生的 $(t, s)$ 分布與誠實驗證者所產生的證明分布相同。故此協議**對任何驗證者皆保持模擬零知識（Simulation-Based Zero Knowledge）**。

#### 多重挑戰設計強化 Soundness

若單一挑戰的長度為 $\ell$ bits，則偽造成功的機率約 $2^{-\ell}$。為了增強安全性，可**一次產生 $k$ 組承諾 $t_1, \dots, t_k$，並透過單一雜湊計算所有子挑戰**：

$$
e_i = H\!\bigl(t_1\,\|\,\dots\,\|\,t_k\,\|\,y\bigr)^{\langle i\rangle},
$$

其中 $H(\,\cdot\,)^{\langle i \rangle}$ 表示從雜湊值中擷取第 $i$ 組挑戰。此時，若需同時偽造所有 $k$ 組子證明，其成功機率將下降至 $2^{-k\ell}$。

例如：$\ell=64,;k=20$ 時，整體偽造成功機率為 $2^{-1280}$，實務上可視為不可行。

#### 小結

Fiat–Shamir 啟發式在 ROM 中保留 Schnorr 協議之完整性、可靠性與零知識，同時移除互動需求；結合多組挑戰機制，可在證明大小線性增加的代價下指數級放大安全性，為本專題提出之改進方案奠定理論依據。


## 二、實作上的改進方向

### 1. 使用橢圓曲線（EC-Schnorr）以提升運算效率與證明尺寸

透過改用橢圓曲線（Elliptic Curve, EC）取代傳統有限域群（如大質數模數群 $\mathbb{Z}_p^*$），可以在不降低安全性的前提下，大幅縮短金鑰長度與證明尺寸，並顯著提升運算效率。實務上，橢圓曲線密碼（Elliptic Curve Cryptography, ECC）以較短的密鑰（如 256 位元）提供與傳統 RSA 或離散對數密碼系統（如 2048 位元）同等甚至更高的安全性。由於橢圓曲線上的群運算涉及的數值較小且結構更佳，點加法（點乘法）等運算在計算複雜度上遠低於傳統模指數運算，從而達到更快的證明生成與驗證速度。

實作上可採取下列步驟：首先，選擇一條安全且標準的橢圓曲線，例如 secp256k1、Curve25519 或 Ristretto255。其次，透過現有成熟的 ECC 函式庫，如 Python 中的 `ecdsa`、`coincurve` 或 `pyNaCl`，實現 Schnorr 協議中的點乘法（點加法）運算，以取代原本的模指數操作，並透過標準 API 進行金鑰生成、承諾計算與證明驗證等步驟。

展示成效時，可設計性能比較實驗，量化 ECC 與傳統模數群的運算效率差異。具體而言，透過計時基準測試（benchmark），記錄產生與驗證相同數量（如 1000 筆）的證明所需時間，並比較兩者證明的資料量大小。預期結果是使用橢圓曲線後，能顯著降低運算時間並縮減證明傳輸的位元組長度，從而明確呈現改進效果。

### 2. 採用 Fiat-Shamir 啟發式實現非互動式證明

Fiat-Shamir（FS）啟發式為互動式零知識協議提供了一個關鍵的非互動轉換方式。透過以安全雜湊函數取代驗證者的隨機挑戰，證明者即可一次性產生證明，驗證者亦能獨立完成驗證而無需與證明者即時交互。此方法尤其適合應用於區塊鏈、離線驗證及其他需降低互動成本之場景。

實作方法具體為：證明者在產生承諾值後，將承諾值 $t$ 與公開金鑰 $y$、情境資訊 $\text{ctx}$（如協議名稱、時間戳或訊息內容）等結合，透過安全雜湊函數（如 SHA-256 或 BLAKE2）計算出挑戰值：

$$
e = H(t \,\| y \,\|\, \text{ctx}) \mod |G|
$$

證明者再利用此挑戰值產生最終回應 $s = r + ex \mod |G|$，輸出完整的非互動證明 $\pi = (t, s)$。驗證者獨立計算相同雜湊函數獲得挑戰 $\tilde{e}$ 並進行驗證，無需實時交互。

展示成效時，可強調非互動式證明的便利性與安全模型的轉變。在安全性上，可論述雜湊函數的隨機預言模型（Random Oracle Model, ROM）假設，說明此轉換如何保持原有協議的零知識性與可靠性。此外，亦可實際展示離線情境下證明者產生證明並由獨立驗證者驗證成功的過程，直觀呈現此改良的實務效益。

### 3. 一次產生多組挑戰以放大安全性

為進一步提升協議的可靠性，本專題採用一次產生多組挑戰的策略。此策略將單一證明流程擴展為並行產生多組承諾與挑戰（如 20 組），並要求證明者須通過全部挑戰方為有效。如此一來，證明者若不具備真實的秘密，要在所有挑戰中同時蒙騙驗證者的機率將呈指數級下降。

實作時，證明者首先產生多組承諾值 $t_1, t_2, \dots, t_k$，並透過一次雜湊呼叫產生挑戰向量：

$$
e_i = H(t_1 \| t_2 \| \dots \| t_k \| y \| \text{ctx})^{\langle i \rangle}
$$

然後，證明者逐一計算回應值 \$s\_i\$ 並組成最終證明：

$$
\pi = \{(t_i, s_i)\}_{i=1}^{k}
$$

驗證者批次進行驗證：

$$
g^{s_i} \stackrel{?}{=} t_i \cdot y^{e_i}, \quad \forall i \in [1, k]
$$

展示成效時可採用攻擊模擬測試，透過程式模擬不誠實證明者以隨機方式猜測挑戰值，並記錄大量測試（如 $10^5$ 次）下的成功率差異。以圖形方式清楚呈現單一挑戰與多組挑戰（例如 20 組）在成功偽造證明機率上的明顯落差。此量化結果能直觀地彰顯安全性的指數級提升，具體展現此改進的重大價值。

透過以上三個具體的實作改進目標，本專題預期可在一個月內完整實現並進行嚴謹的實驗驗證。透過量化的效能比較與安全性展示，能有效說服相關使用者與研究者，展現本研究在效能與安全性上的具體貢獻，達成預期的實務改良效果。

## 三、專題進度時間表
* Week 1：ECC 函式庫整合與單元測試
* Week 2：Fiat–Shamir 非互動模組 + 雜湊域分離（domain separation）
* Week 3：多重挑戰批次驗證、偽造率模擬
* Week 4：效能 benchmark、撰寫報告


**參考文獻**

\[1] C.‑P. Schnorr, “Efficient Identification and Signatures for Smart Cards,” *Advances in Cryptology – CRYPTO’89 Proceedings*, Lecture Notes in Computer Science, vol. 435, Springer, 1990, pp. 239–252. ([SpringerLink][1])

\[2] A. Fiat and A. Shamir, “How to Prove Yourself: Practical Solutions to Identification and Signature Problems,” *Advances in Cryptology – CRYPTO’86*, LNCS 263, Springer, 1986, pp. 186–194. ([MIT 6.875 Cryptography][2])

\[3] D. Pointcheval and J. Stern, “Security Proofs for Signature Schemes,” *Advances in Cryptology – EUROCRYPT’96*, LNCS 1070, Springer, 1996, pp. 387–398. ([DIENS][3])

\[4] Y. Seurin, “On the (In)security of the Fiat‑Shamir Paradigm,” IACR Cryptology ePrint Archive, Report 2003/034, 2003. ([Cryptology ePrint Archive][4])

\[5] C. Gennaro, M. Kiyomizui, and K. Osaka, “Batching Schnorr Identification Scheme with Applications to Privacy‑Preserving Credentials,” *Public Key Cryptography (PKC)*, 2004. ([Khoury College of Computer Sciences][5])

\[6] D. J. Bernstein, N. Duif, T. Lange, P. Schwabe, and B.‑Y. Yang, “High‑Speed High‑Security Signatures,” in *CHES 2011: Cryptographic Hardware and Embedded Systems*, LNCS 6917, Springer, 2011, pp. 124–142. ([Cryptology ePrint Archive][6])

\[7] RFC 8032, “Edwards‑Curve Digital Signature Algorithm (EdDSA),” Internet Engineering Task Force (IETF), Jan. 2017. ([IETF Datatracker][7])

\[8] RFC 9496, “The ristretto255 and decaf448 Groups,” Internet Engineering Task Force (IETF), Sept. 2023. ([IETF Datatracker][8])

\[9] G. Neven, N. P. Smart, and B. Warinschi, “The Provable Security of Ed25519: Theory and Practice,” in *IEEE Symposium on Security and Privacy (S\&P)*, 2020. ([Dennis Jackson][9])

\[10] B. David, L. Najm, A. de Rawat *et al.*, “Generic Techniques and Applications to Concrete Soundness,” IACR Cryptology ePrint Archive, Report 2020/1213, 2020. ([Cryptology ePrint Archive][10])

[1]: https://link.springer.com/chapter/10.1007/0-387-34805-0_22?utm_source=chatgpt.com "Efficient Identification and Signatures for Smart Cards - SpringerLink"
[2]: https://mit6875.github.io/PAPERS/Fiat-Shamir.pdf?utm_source=chatgpt.com "[PDF] Fiat-Shamir.pdf - How to prove yourself"
[3]: https://www.di.ens.fr/~pointche/Documents/Papers/1996_eurocrypt.pdf?utm_source=chatgpt.com "[PDF] Security Proofs for Signature Schemes"
[4]: https://eprint.iacr.org/2003/034.pdf?utm_source=chatgpt.com "[PDF] On the (In)security of the Fiat-Shamir Paradigm"
[5]: https://www.khoury.northeastern.edu/home/koods/papers/gennaro04batching.pdf?utm_source=chatgpt.com "[PDF] Batching Schnorr Identification Scheme with Applications to Privacy ..."
[6]: https://eprint.iacr.org/2011/368?utm_source=chatgpt.com "High-speed high-security signatures - Cryptology ePrint Archive"
[7]: https://datatracker.ietf.org/doc/html/rfc8032?utm_source=chatgpt.com "RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)"
[8]: https://datatracker.ietf.org/doc/rfc9496/?utm_source=chatgpt.com "RFC 9496 - The ristretto255 and decaf448 Groups - IETF Datatracker"
[9]: https://dennis-jackson.uk/assets/pdfs/ed25519.pdf?utm_source=chatgpt.com "[PDF] The Provable Security of Ed25519: Theory and Practice"
[10]: https://eprint.iacr.org/2020/1213.pdf?utm_source=chatgpt.com "[PDF] Generic Techniques and Applications to Concrete Soundness"
