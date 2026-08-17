// examples/Example2_Flattened.java
public class Fee {
    // Original:
    //   if (amount <= 0) throw new IllegalArgumentException();
    //   int fee = amount < 1000 ? 50 : amount / 20;
    //   if (isPremium) fee = fee / 2;
    //   return fee;
    public static int compute(int amount, boolean isPremium) {
        int fee = 0;
        int s = 7;
        while (true) {
            switch (s) {
                case 7: s = (amount <= 0) ? 2 : 5; break;
                case 2: throw new IllegalArgumentException();
                case 5: s = (amount < 1000) ? 1 : 4; break;
                case 1: fee = 50;            s = 3; break;
                case 4: fee = amount / 20;   s = 3; break;
                case 3: s = isPremium ? 6 : 8; break;
                case 6: fee = fee / 2;       s = 8; break;
                case 8: return fee;
            }
        }
    }
}
