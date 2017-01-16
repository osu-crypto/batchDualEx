#pragma once 
#include <array>
#include "cryptoTools/Common/Defines.h"
#include <ostream>
#include <iomanip> 

namespace osuCrypto{
   typedef u64 Wire;

   //struct  GarbledWire
   //{
   //public:
   //   GarbledWire(){}

   //   GarbledWire(const block& l0)
   //      :Label0(l0)
   //   {
   //   }

   //   inline const block Label1(block&globalOffset) const
   //   {
   //      return Label0 ^ globalOffset;
   //   }


   //   block Label0;
   //private:
   //};


   inline u8 PermuteBit(const block& b)
   {
      return ByteArray(b)[0] & 1;
   }

   //inline u8 PermuteBit(const GarbledWire& wire)
   //{
   //   return PermuteBit(wire);
   //}
}
