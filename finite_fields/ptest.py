p = 16798108731015832284940804142231733909759579603404752749028378864165570215949L
u = 8
q = (p**u - 1)/(p-1)/37


from modp import IntegersModP
from finitefield import FiniteField, generateIrreduciblePolynomial
from polynomial import polynomialsOver



Zpu = IntegersModP(p**u)
Poly = polynomialsOver(Zpu).factory
#f = Poly([3,0,0,0, 0,0,0,1])
#Fpu = FiniteField(p,u, polynomialModulus=f)

