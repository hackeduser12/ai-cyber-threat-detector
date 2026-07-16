// Seeded pseudo-random number generator for reproducible synthetic datasets
export class SeededRandom {
  private a: number;
  private b: number;
  private c: number;
  private d: number;

  constructor(seed: number) {
    let h = seed ^ 0xDEADBEEF;
    h = Math.imul(h ^ (h >>> 16), 2246822507);
    h = Math.imul(h ^ (h >>> 13), 3266489909);
    const s = h ^ (h >>> 16);
    this.a = s >>> 0;
    this.b = (s + 1) >>> 0;
    this.c = (s + 2) >>> 0;
    this.d = (s + 3) >>> 0;
  }

  // Returns a float between 0 and 1
  next(): number {
    this.a >>>= 0; this.b >>>= 0; this.c >>>= 0; this.d >>>= 0;
    let t = (this.a + this.b) | 0;
    this.a = this.b ^ (this.b >>> 9);
    this.b = (this.c + (this.c << 3)) | 0;
    this.c = (this.c << 21) | (this.c >>> 11);
    this.d = (this.d + 1) | 0;
    t = (t + this.d) | 0;
    this.c = (this.c + t) | 0;
    return (t >>> 0) / 4294967296;
  }

  // Exponential distribution
  exponential(scale: number): number {
    return -Math.log(1 - this.next()) * scale;
  }

  // Poisson distribution using Knuth's method
  poisson(lambda: number): number {
    const L = Math.exp(-lambda);
    let k = 0;
    let p = 1;
    // For large lambda, Knuth's method can be slow. Since lambda can be 500, we use a Gaussian approximation for lambda > 30.
    if (lambda > 30) {
      const g = this.normal(lambda, Math.sqrt(lambda));
      return Math.max(0, Math.round(g));
    }
    do {
      k++;
      p *= this.next();
    } while (p > L);
    return k - 1;
  }

  // Normal distribution using Box-Muller transform
  normal(mean: number, stdDev: number): number {
    let u = 0, v = 0;
    while (u === 0) u = this.next();
    while (v === 0) v = this.next();
    const num = Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
    return num * stdDev + mean;
  }

  // Binomial distribution
  binomial(n: number, p: number): number {
    let successes = 0;
    for (let i = 0; i < n; i++) {
      if (this.next() < p) {
        successes++;
      }
    }
    return successes;
  }

  // Uniform distribution [low, high)
  uniform(low: number, high: number): number {
    return this.next() * (high - low) + low;
  }

  // Random integer [low, high]
  randint(low: number, high: number): number {
    return Math.floor(this.next() * (high - low + 1)) + low;
  }
}

export interface Sample {
  id: string;
  Duration_Sec: number;
  Packet_Count: number;
  Bytes_Transferred: number;
  Failed_Login_Attempts: number;
  Label: number; // 0 = Benign, 1 = Threat
}

// ----------------------------------------------------
// Synthetic Data Generation
// ----------------------------------------------------
export function generateSyntheticData(nSamples = 1000, seed = 42): Sample[] {
  const rng = new SeededRandom(seed);
  const data: Sample[] = [];

  const normalCount = Math.floor(nSamples * 0.8);
  const maliciousCount = nSamples - normalCount;

  // Generate Normal (Benign) Traffic
  for (let i = 0; i < normalCount; i++) {
    const duration = rng.exponential(5);
    const packets = rng.poisson(50);
    const bytes = Math.max(100, packets * rng.normal(500, 100));
    const failedLogins = rng.binomial(1, 0.05);

    data.push({
      id: `benign-${i}`,
      Duration_Sec: Math.round(duration * 100) / 100,
      Packet_Count: packets,
      Bytes_Transferred: Math.round(bytes),
      Failed_Login_Attempts: failedLogins,
      Label: 0,
    });
  }

  // Generate Malicious (Threat) Traffic
  for (let i = 0; i < maliciousCount; i++) {
    const duration = rng.uniform(10, 300);
    const packets = rng.poisson(500);
    const bytes = Math.max(1000, packets * rng.normal(1200, 300));
    const failedLogins = rng.randint(3, 15);

    data.push({
      id: `threat-${i}`,
      Duration_Sec: Math.round(duration * 100) / 100,
      Packet_Count: packets,
      Bytes_Transferred: Math.round(bytes),
      Failed_Login_Attempts: failedLogins,
      Label: 1,
    });
  }

  // Shuffle the dataset using Fisher-Yates
  for (let i = data.length - 1; i > 0; i--) {
    const j = Math.floor(rng.next() * (i + 1));
    const temp = data[i];
    data[i] = data[j];
    data[j] = temp;
  }

  return data;
}

// ----------------------------------------------------
// Machine Learning Framework (Decision Tree & Random Forest)
// ----------------------------------------------------
export interface TreeNode {
  feature?: keyof Omit<Sample, 'Label' | 'id'>;
  threshold?: number;
  left?: TreeNode;
  right?: TreeNode;
  isLeaf: boolean;
  value?: number; // Probability of class 1 (Threat)
  giniDecrease?: number; // Accumulated Gini reduction for feature importance
  samplesCount?: number;
}

export class DecisionTreeClassifier {
  private maxDepth: number;
  private minSamplesSplit: number;
  private root!: TreeNode;
  private featureImportance: Record<string, number> = {
    Duration_Sec: 0,
    Packet_Count: 0,
    Bytes_Transferred: 0,
    Failed_Login_Attempts: 0,
  };

  constructor(maxDepth = 5, minSamplesSplit = 2) {
    this.maxDepth = maxDepth;
    this.minSamplesSplit = minSamplesSplit;
  }

  fit(Xy: Sample[], featureSubset?: (keyof Omit<Sample, 'Label' | 'id'>)[]) {
    const features: (keyof Omit<Sample, 'Label' | 'id'>)[] = featureSubset || [
      'Duration_Sec',
      'Packet_Count',
      'Bytes_Transferred',
      'Failed_Login_Attempts',
    ];

    this.root = this.buildTree(Xy, 0, features);
    this.calculateImportances(this.root, Xy.length);
  }

  private calculateGini(groups: Sample[][]): number {
    let gini = 0;
    const totalSamples = groups.reduce((sum, g) => sum + g.length, 0);
    if (totalSamples === 0) return 0;

    for (const group of groups) {
      const groupSize = group.length;
      if (groupSize === 0) continue;

      let score = 0;
      // Probability of Benign (0)
      const benignCount = group.filter((s) => s.Label === 0).length;
      const p0 = benignCount / groupSize;
      score += p0 * p0;

      // Probability of Threat (1)
      const p1 = (groupSize - benignCount) / groupSize;
      score += p1 * p1;

      gini += (1.0 - score) * (groupSize / totalSamples);
    }
    return gini;
  }

  private testSplit(
    feature: keyof Omit<Sample, 'Label' | 'id'>,
    threshold: number,
    dataset: Sample[]
  ) {
    const left: Sample[] = [];
    const right: Sample[] = [];
    for (const sample of dataset) {
      if (sample[feature] < threshold) {
        left.push(sample);
      } else {
        right.push(sample);
      }
    }
    return { left, right };
  }

  private buildTree(
    dataset: Sample[],
    depth: number,
    features: (keyof Omit<Sample, 'Label' | 'id'>)[]
  ): TreeNode {
    const threatsCount = dataset.filter((s) => s.Label === 1).length;
    const totalSamples = dataset.length;
    const leafValue = totalSamples === 0 ? 0 : threatsCount / totalSamples;

    // Base cases
    if (
      totalSamples < this.minSamplesSplit ||
      depth >= this.maxDepth ||
      threatsCount === 0 ||
      threatsCount === totalSamples
    ) {
      return { isLeaf: true, value: leafValue, samplesCount: totalSamples };
    }

    let bestFeature: keyof Omit<Sample, 'Label' | 'id'> | null = null;
    let bestThreshold = 0;
    let bestGini = 999;
    let bestGroups: { left: Sample[]; right: Sample[] } | null = null;
    const parentGini = this.calculateGini([dataset]);

    for (const feature of features) {
      const values = dataset.map((s) => s[feature]);
      const min = Math.min(...values);
      const max = Math.max(...values);

      if (min === max) continue;

      // Test 15 candidate split points
      for (let i = 1; i <= 15; i++) {
        const threshold = min + (max - min) * (i / 16);
        const groups = this.testSplit(feature, threshold, dataset);
        const gini = this.calculateGini([groups.left, groups.right]);

        if (gini < bestGini) {
          bestGini = gini;
          bestFeature = feature;
          bestThreshold = threshold;
          bestGroups = groups;
        }
      }
    }

    if (!bestFeature || !bestGroups || bestGroups.left.length === 0 || bestGroups.right.length === 0) {
      return { isLeaf: true, value: leafValue, samplesCount: totalSamples };
    }

    const giniDecrease = parentGini - bestGini;

    const leftNode = this.buildTree(bestGroups.left, depth + 1, features);
    const rightNode = this.buildTree(bestGroups.right, depth + 1, features);

    return {
      isLeaf: false,
      feature: bestFeature,
      threshold: bestThreshold,
      left: leftNode,
      right: rightNode,
      giniDecrease,
      samplesCount: totalSamples,
    };
  }

  private calculateImportances(node: TreeNode, totalSize: number) {
    if (node.isLeaf || !node.feature) return;

    const weight = (node.samplesCount ?? 0) / totalSize;
    const decrease = (node.giniDecrease ?? 0) * weight;
    this.featureImportance[node.feature] = (this.featureImportance[node.feature] || 0) + decrease;

    if (node.left) this.calculateImportances(node.left, totalSize);
    if (node.right) this.calculateImportances(node.right, totalSize);
  }

  getImportance(): Record<string, number> {
    return this.featureImportance;
  }

  predict(sample: Omit<Sample, 'Label' | 'id'>): number {
    return this.predictNode(this.root, sample);
  }

  private predictNode(node: TreeNode, sample: Omit<Sample, 'Label' | 'id'>): number {
    if (node.isLeaf) {
      return node.value ?? 0;
    }
    const val = sample[node.feature!];
    if (val < node.threshold!) {
      return this.predictNode(node.left!, sample);
    } else {
      return this.predictNode(node.right!, sample);
    }
  }
}

export class RandomForestClassifier {
  private nEstimators: number;
  private maxDepth: number;
  private minSamplesSplit: number;
  private trees: DecisionTreeClassifier[] = [];
  private accuracy = 0;
  private featureImportances: Record<string, number> = {
    Duration_Sec: 0,
    Packet_Count: 0,
    Bytes_Transferred: 0,
    Failed_Login_Attempts: 0,
  };

  constructor(nEstimators = 10, maxDepth = 5, minSamplesSplit = 2) {
    this.nEstimators = nEstimators;
    this.maxDepth = maxDepth;
    this.minSamplesSplit = minSamplesSplit;
  }

  fit(dataset: Sample[]) {
    // 80-20 train-test split
    const trainSize = Math.floor(dataset.length * 0.8);
    const trainSet = dataset.slice(0, trainSize);
    const testSet = dataset.slice(trainSize);

    this.trees = [];
    const features: (keyof Omit<Sample, 'Label' | 'id'>)[] = [
      'Duration_Sec',
      'Packet_Count',
      'Bytes_Transferred',
      'Failed_Login_Attempts',
    ];

    const rng = new SeededRandom(1337);

    for (let i = 0; i < this.nEstimators; i++) {
      const tree = new DecisionTreeClassifier(this.maxDepth, this.minSamplesSplit);

      // Bootstrap sample (with replacement)
      const bootstrap: Sample[] = [];
      for (let j = 0; j < trainSet.length; j++) {
        const index = Math.floor(rng.next() * trainSet.length);
        bootstrap.push(trainSet[index]);
      }

      // Feature bagging: randomly select 3 features out of 4 for each split
      const shuffledFeatures = [...features];
      for (let f = shuffledFeatures.length - 1; f > 0; f--) {
        const rIndex = Math.floor(rng.next() * (f + 1));
        const temp = shuffledFeatures[f];
        shuffledFeatures[f] = shuffledFeatures[rIndex];
        shuffledFeatures[rIndex] = temp;
      }
      const selectedFeatures = shuffledFeatures.slice(0, 3);

      tree.fit(bootstrap, selectedFeatures);
      this.trees.push(tree);
    }

    // Accumulate and average feature importances
    const rawImportances: Record<string, number> = {
      Duration_Sec: 0,
      Packet_Count: 0,
      Bytes_Transferred: 0,
      Failed_Login_Attempts: 0,
    };

    for (const tree of this.trees) {
      const imp = tree.getImportance();
      for (const feat of features) {
        rawImportances[feat] += imp[feat] || 0;
      }
    }

    // Normalize importances to sum to 1.0
    const sum = Object.values(rawImportances).reduce((a, b) => a + b, 0) || 1;
    for (const feat of features) {
      this.featureImportances[feat] = rawImportances[feat] / sum;
    }

    // Evaluate test set accuracy
    let correct = 0;
    for (const sample of testSet) {
      const pred = this.predict(sample).prediction;
      if (pred === sample.Label) {
        correct++;
      }
    }
    this.accuracy = testSet.length > 0 ? correct / testSet.length : 1.0;
  }

  getDiagnostics() {
    return {
      accuracy: this.accuracy,
      featureImportances: this.featureImportances,
    };
  }

  predict(sample: Omit<Sample, 'Label' | 'id'>): { prediction: number; confidence: number } {
    let sumProba = 0;
    for (const tree of this.trees) {
      sumProba += tree.predict(sample);
    }
    const avgProba = sumProba / this.trees.length; // Probability of Threat (1)

    if (avgProba >= 0.5) {
      return { prediction: 1, confidence: avgProba };
    } else {
      return { prediction: 0, confidence: 1 - avgProba };
    }
  }
}
